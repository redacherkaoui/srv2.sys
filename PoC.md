# Targeting Kernel Vulnerabilities in Modern Windows Systems

Targeting kernel vulnerabilities in modern Windows systems—especially in core components like the SMB2 server (`srv2.sys`)—is vastly more complex than in the past. In the days of SMBv1, researchers could often hit vulnerable code paths using minimal authentication or even unauthenticated requests. Today, however, the reality is different: **most of the attack surface in `srv2.sys` is locked behind robust, multi-step authentication—specifically, the NTLMSSP protocol, wrapped in SPNEGO and enforced by both kernel and usermode code.**

---

## The Wall: Authentication

Suppose you discover or want to reach a vulnerability in the SMB2 server code on a recent Windows 10/11 system. You analyze the code and see that the bug—maybe a buffer overflow or a bad pointer dereference—lives in a handler deep inside `srv2.sys`. You craft what you believe is a minimal test case: an SMB2 packet with the precise layout and values to trigger the bug.

But when you fire your PoC at the server, the response is cold: the server drops your packet, returns an error, or closes the connection. **What’s wrong?** : Authentication.

Almost all of the interesting SMB2 attack surface is now “behind the door” of authenticated access. Modern Windows servers require a valid authentication handshake before they will even look at the more complex parts of the protocol. *This is not just a policy: it is enforced in the protocol logic, in both the kernel and usermode.*

---

## Steps Required to Reach Target Code in `srv2.sys`

To reach your target code in `srv2.sys`, you have to perform a legitimate SMB2 session setup, which includes several critical steps:

### 1. SMB2 NEGOTIATE

You must begin by negotiating protocol dialects with the server, providing details like supported SMB versions (2.0.2, 2.1, 3.0, 3.0.2, 3.1.1), capabilities, client GUIDs, and in modern versions, negotiate contexts for things like pre-auth integrity.

### 2. SMB2 SESSION_SETUP

Next, you must perform a `SESSION_SETUP` request, which is where authentication takes place. This is not a single packet; it is a multi-step exchange:

- The client sends a `SESSION_SETUP` with a security blob: a SPNEGO (Simple and Protected GSS-API Negotiation Mechanism) token, which typically wraps an NTLMSSP (NT LAN Manager Security Support Provider) message.
- The server responds with a `SESSION_SETUP` reply containing its own security blob, often an NTLMSSP “challenge”.
- The client must reply with an authenticator—a calculated response using the server’s challenge, and possibly a Message Integrity Code (MIC) if session security demands it.
- In some cases, an additional MIC roundtrip is required before full authentication succeeds.

*If you fail to follow this choreography, the server will not grant you a valid session.*

Any attempt to shortcut this process—such as by replaying captured tokens or using anonymous/guest access—will almost always fail, especially against patched or domain-joined servers.

---

## The NTLMSSP Obstacle

The crux of the authentication handshake is the NTLMSSP protocol, which implements a stateful challenge-response scheme. Here’s what makes this protocol a major obstacle and, paradoxically, a secondary attack surface:

- **Statefulness:** Each step in NTLMSSP must reference previous states and values (flags, challenges, session keys, etc.). The protocol is not stateless; every token you send or receive must be constructed according to the running “context” held in both client and server memory.
- **Strict Validation:** Both client and server check fields such as message signatures, lengths, offsets, flags, and checksums. Invalid or replayed messages are rejected.
- **User-Mode and Kernel Involvement:** NTLMSSP is implemented across user-mode, and kernel (via the SMB2 server in `srv2.sys`). This dual-layered enforcement means you cannot simply fake or replay authentication traffic without deep protocol emulation.

---

## Practical Requirements for Reaching a Kernel Bug

To reach any interesting kernel bug in SMB2, your PoC must:

- **Dynamically construct valid SPNEGO/NTLMSSP tokens.**
  - This usually means invoking the Windows SSPI (Security Support Provider Interface) APIs, so that tokens are built and cryptographically signed using real credentials, session keys, and server challenges.
- **Track and manage the full negotiation state:**
  - You must parse and store server responses, extract offsets, handle negotiate contexts, and adjust subsequent requests based on server-chosen parameters.
- **Handle authentication corner cases**, such as requiring a MIC if the server enforces signing or integrity.
- **Correctly align and pad your packets** according to protocol requirements, or risk immediate rejection.

*If any part of your authentication state machine is wrong—incorrect flags, mismatched lengths, or stale challenge responses—the server will refuse further packets, and your target bug remains unreachable.*

---

## Irony: Authentication Itself Is a Potential Attack Surface

Ironically, the authentication mechanism that blocks access to kernel bugs is itself full of risky legacy code:

- **Complexity and Legacy:** NTLMSSP is a decades-old protocol with a large attack surface, including memory management bugs, unchecked offsets, weak signature checks, and possible cryptographic implementation issues.
- **Parsing Bugs:** Both the server and client parse variable-length security tokens that come from the network. Any parsing bug in this phase can be exploited even before reaching the actual SMB payload handler.

> *Almost all practical SMB2 kernel vulnerability research today is bottlenecked by the need to fully, correctly, and dynamically implement the authentication handshake.*

---

## Bottom Line

If you cannot produce a valid authenticated session, your PoC will never even tickle the vulnerable code in the kernel. Worse, getting NTLMSSP right is non-trivial; you must either:

- **Call the OS’s SSPI APIs with valid credentials** (the only reliable way), or
- **Reimplement the full NTLMSSP protocol stack**, handling all edge cases, signing, and key negotiation (which is virtually never done for serious research).
