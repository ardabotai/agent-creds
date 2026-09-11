# Companion architecture and roadmap

Current implementation: native iPhone/iPad companion, QR owner enrollment,
Secure Enclave-protected phone unlock, signed credential approvals, vault
management, and a deployed Cloudflare relay for use across networks while the
Mac stays online. See [iOS setup](../ios/README.md) and [relay operations](../relay/README.md)
for the implemented protocol, current deployment and validation boundaries.

The QR flow uses a ten-minute invitation, rotates credentials after enrollment,
and persists trusted pairing in device-local Keychain. The relay sees routing
metadata and ciphertext but cannot decrypt vault operations. Phone authentication
signs each protected command against a fresh Mac challenge; the Mac verifies
current policy and request state before issuing a temporary proxy handle.

Push registration, private alert payloads and bounded delivery retry are implemented.
Live APNs signing/provisioning, physical Face ID and camera pairing, and background
cellular delivery remain unverified. Universal Link entitlements are present, but
AASA deployment on the approval-link domain and signed-device proof remain separate.
Native approval links are supported by the installed apps.

## Product direction

The local vault keeps credentials and execution on the Mac. The paid version is
planned as a hosted vault with a separate cloud execution service, allowing the Mac
to be offline. See [product tiers](product-tiers.md). Do not treat the deployed relay
as hosted vault storage or describe a credential-using cloud executor as fully
zero-knowledge. Manual [offline signing](offline-approvals.md) is a future fallback;
the relay is the chosen primary approval experience.

## Remaining work

- Provision APNs and validate alert → review → Face ID → redeem on a real iPhone
  over cellular, plus permission denial, background/locked app, and Mac sleep/wake.
- Deploy the Universal Link association and installation fallback on the approval
  domain without exposing request metadata to previews or third-party scripts.
- Add authenticated agent identities. Current agent labels are client-supplied;
  redemption is protected by a private request capability, not the display name.
- Add optional durable pending-request recovery only with explicit non-replay
  semantics. Current daemon restart invalidates pending requests and challenges.
- Add paid account enrollment, quotas, recovery and hosted execution boundaries
  before broad hosted-vault distribution.

## Acceptance boundaries

An approval URL or notification must never itself authorize access. Signed grants
must bind device, credential version, purpose, destinations, duration, expiry and
request identity. The authoritative service rejects stale, altered, revoked and
already-decided requests. Root credentials and key material never appear in agent
responses, notification text, URLs or logs. Tests use temporary synthetic vaults;
a successful build or synthetic live relay test does not prove physical biometrics,
APNs delivery, App Store availability or a deployed hosted vault.
