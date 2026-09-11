# Local and hosted vault products

User direction: the paid version should offer a hosted cloud vault.

## Local vault

The vault and credential execution remain on the user's Mac. The encrypted relay
connects paired iPhones across networks and delivers approval notifications after
Apple push provisioning. The phone or Mac can independently approve operations;
the Mac must be online to execute them. QR pairing and biometric approval remain
the primary experience. Manual offline signing is a possible future fallback.

## Paid hosted vault (planned, not implemented)

Encrypted vault storage and credential execution move to an account-scoped cloud
service so the Mac can be offline. Both Mac and iPhone become owner clients with
local authentication and device-bound signing/decryption keys.

This requires more than reusing the relay:

- Account identity, subscription/entitlement checks, tenant isolation and quotas.
- Per-device wrapping, key recovery, device revocation and key-rotation workflows.
- A separate execution service that accepts only expiring, one-time, scoped owner
  grants and performs allowed upstream requests without returning stored secrets
  to agents. Decryption material exists transiently during authorized execution.
- Durable request/redemption state, audit trails, backups and tested recovery.
- Controls for outbound destinations, redirects, credentials in logs, request-body
  handling, encryption keys and access by service operators.

The relay must remain unable to decrypt vault traffic. A hosted executor that
uses credentials transiently is not fully zero-knowledge; describe that boundary
accurately. Billing, hosted vault storage and execution are not deployed by the
current relay work.
