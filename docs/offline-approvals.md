# Offline approval transport proposal

Status: proposed transport, not implemented. This can replace the relay for manual
approval delivery while keeping the existing Mac vault and scoped egress proxy.
It does not by itself deliver push notifications or synchronize vault metadata.

## Flow

1. Initial QR pairing pins both device identities. The Mac stores the phone's
   signing public key; the phone stores the Mac's signing public key and its
   existing Secure Enclave-protected vault-key capsule.
2. The Mac creates an immutable, expiring request and a fresh request-specific
   encryption key pair. It signs a request containing its identity, the phone
   identity, request ID, nonce, credential version, purpose, allowed destinations,
   duration limit, expiry, and the request's encryption public key.
3. The agent shows an app deep link carrying the signed request. Use an encrypted
   payload where practical and never include secrets or redemption capabilities.
   The app verifies the pinned Mac signature before presenting any approval UI.
   The URL is untrusted input, not proof that the user requested an operation.
4. The phone shows the verified request, authenticates with Face ID/passcode, and
   signs a narrowly scoped approval. For the current passkey-vault architecture,
   it also unwraps the phone's key capsule and encrypts the authorized key-release
   command to the request-specific Mac public key. The code shown to the user is
   an opaque sealed grant, not plaintext key material or an unrestricted token.
5. The user copies/shares that approval code to the originating agent. A dedicated
   redemption tool accepts it together with the agent's private request capability.
6. The Mac authenticates and decrypts the grant, checks the registered phone,
   original request digest, nonce, expiry, current credential version and policy,
   and atomically consumes the decision. Only then does it issue a scoped proxy
   handle. Duplicate, expired, revoked, altered and wrong-agent grants fail closed.

## Required changes

- Persist a Mac signing identity and pin it during QR pairing.
- Add request-specific encryption keys and signed request serialization.
- Add a separate strictly parsed offline-review deep-link route with size limits.
- Add a phone review screen that works without a network fetch and labels the
  pinned Mac, requested scope and expiry. Offline metadata must not be presented
  as a live vault snapshot.
- Add explicit Copy/Share approval-code actions. Never copy a raw vault key.
- Add capability-bound, one-time sealed-grant redemption to MCP and tests for
  tampering, cross-request/cross-device substitution, replay and revocation.
- Keep expiry and revocation authoritative on the Mac. A phone can sign while
  offline, but the Mac can still refuse a grant that became stale before redemption.
- Mac restart invalidates in-memory requests and request encryption private keys.
  Long-lived device pairing is separate from short-lived request validity.

A bare signature is insufficient for a passkey vault: it proves approval but
cannot create the decryption key. The sealed grant carries the necessary material
without exposing it to the agent. The Mac must be online when the agent redeems
and uses the credential, but the phone does not need a live connection to the Mac.
