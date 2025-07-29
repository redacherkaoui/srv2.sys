## 1. Vulnerable Call Path

1. **SMB2 Record Reassembly**
   The native network driver (`srvnet.sys`) reads the 4‑byte SMB2 “record header” (length) and then the full payload, buffering it until the complete record is available .

2. **SMB2 Dispatch in `srv2.sys`**

   ```c
   ProbeForRead(fullPacket, packetLen, 1);
   Smb2ValidateHeader(fullPacket);
   if (header->Command == SMB2_CREATE)
       Srv2CommonCreate(...);
   ```

   The handler extracts:

   ```c
   contextsPtr    = packet + CreateContextsOffset;
   contextsLength = CreateContextsLength;
   ProbeForRead(contextsPtr, contextsLength, 1);
   Srv2EnumerateContexts(contextsPtr, contextsLength);
   ```

   Each `SMB2_CREATE_CONTEXT` entry is checked so that
   `DataOffset + DataLength ≤ contextsLength` .

3. **Security‑Descriptor Context Handler**
   The function responsible—often decompiled as `FUN_1c0058b10`—builds a per‑create heap buffer, but then mistakenly copies *the entire* contexts blob into the small buffer:

   ```c
   // 1) Allocate just header + sdLength
   allocSize = headerSize + sdLength;
   buf       = ExAllocatePoolWithTag(NonPagedPool, allocSize, 'Ctx ');
   RtlZeroMemory(buf, allocSize);

   // … copy other sub‑contexts correctly …

   // 2) Flawed copy: uses full blob length, not sdLength
   memmove(buf + sdOffset,
           contextsPtr + DataOffset,
           contextsLength);    // <-- attacker‑controlled overall size :contentReference[oaicite:8]{index=8}
   ```

   Because `contextsLength` can be set much larger than `sdLength`, this overruns the heap buffer by `(contextsLength – sdLength)` bytes, corrupting adjacent non‑paged pool blocks.

---

## 2. Root Cause

* **Heap Allocation Size**
  Determined by the *per‑context* field (`DataLength`) for the Security‑Descriptor entry.

* **Copy Length**
  Erroneously taken from the *global* `CreateContextsLength` (the full blob size), rather than the context’s own `DataLength` .

By crafting a small `DataLength` (e.g. 0x80 bytes) but inflating `CreateContextsLength` to just under the negotiated maximum (e.g. 0x1000 bytes), an attacker forces a large heap‑overflow in `srv2.sys`.

---

## 3. Impact & Exploitation Potential

* **Heap Corruption**
  Overwriting the next non‑paged pool block’s metadata (POOL\_HEADER or lookaside pointers) provides an arbitrary‑write primitive.

* **Kernel Read/Write**
  Corrupting the MDL for the CREATE response can turn into an information leak or further writes on completion.

* **Full RCE Path**
  With controlled heap corruption, an attacker can bypass DEP/SMEP (via ROP), defeat KASLR (via leaks), and execute arbitrary kernel code.

---

## 4. Mitigations

Microsoft’s MS17‑010 update hardened both SMBv1 and SMB2 paths to eliminate this pattern by:

1. **Safe‑math on length sums**
   Overflow checks on every addition of length fields.

2. **Per‑block bounds**
   Always using each context’s declared length for `memmove`, never the aggregate.

3. **Early size caps**
   Rejecting any request that exceeds negotiated maxima or available pool memory .

---

### Takeaway

The heap overflow in `srv2.sys` arises from a classic “allocate‑then‑global‑copy” mistake in the Security‑Descriptor context builder. While the full exploit requires precise pool grooming and mitigation bypasses, the core bug is a simple mismatch between allocation size and copy length.

Understanding this minimal logic—and the small two‑line snippet above—gives clear insight into both the vulnerability and why the MS17‑010 fixes were necessary.
