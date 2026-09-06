# AgentCreds companion

Native SwiftUI app for iPhone and iPad (iOS 17+). Open
`ios/AgentCreds.xcodeproj`, choose the `AgentCreds` scheme, select your Apple
Development Team, and run on an iPhone. Regenerate the checked-in project with
`python3 ios/generate-project.py`.

## QR pairing and remote use

1. Run the updated Mac app and choose **Pair iPhone** from its menu.
2. On iPhone, tap **Scan Mac Code**. Both devices need internet access; they do not
   need the same network. The code expires after ten minutes. A secure manual
   pairing field is available if scanning is unavailable.
3. Authenticate on the iPhone, then confirm **Trust this iPhone** once on the Mac.
   A passkey vault also asks for its passkey ceremony during this enrollment.
4. After enrollment, the phone receives fresh connection credentials and the QR
   credentials stop working. Trusted pairing is stored in device-local Keychain,
   survives Mac restarts, and expires after one year. A lost enrollment response
   requires a new pairing; there is no silent trust fallback.
5. Allow approval notifications. **Devices → Approval notifications** shows OS
   permission separately from relay push-provisioning status.

The deployed relay is `https://agentcreds-relay.agentcreds-relay.workers.dev`.
The Mac connects outward using a persistent authenticated WebSocket; the iPhone
opens short-lived channels as needed. No public Mac listener or router port
forwarding is required. The legacy LAN transport is retained for tests and older
callers, but the Mac app's Pair iPhone flow uses the relay.

The Mac must stay online. Reconnection discards old challenges and does not replay
vault commands. If a connection drops during a change, refresh to check the result
before trying again. Pending requests expire after ten minutes; Mac restart
invalidates them rather than resurrecting old approvals.

## Vault management and approvals

The iPhone can add credentials, replace a stored value, edit destinations and
Bearer/Basic/custom-header settings, delete credentials, and review audit activity.
Stored values are not displayed. Trusted-owner operations use Face ID/Touch ID or
the device passcode and require no second Mac prompt. The Mac remains independently
usable with its normal Keychain/passkey ceremony.

Agents call `request_approval(name, purpose)` and show the returned `app_url`.
Opening it shows the authoritative request and does not approve anything. After
phone approval, the agent redeems a scoped temporary proxy handle once using its
private `redemption_token`. No stored credential or vault key is returned to the
agent. The client-supplied agent name/purpose are explicitly labeled; they are not
an authenticated agent identity.

Existing LAN pairings can use **Devices → Enable iPhone control** for owner
enrollment, but should pair again through the updated Mac QR flow for relay access.

## Cryptographic trust

Each iPhone creates separate Secure Enclave P-256 signing and key-agreement keys
with `privateKeyUsage` + `userPresence` and `WhenPasscodeSetThisDeviceOnly` protection.
Face ID/Touch ID or the passcode authorizes their use. There is no software-key
fallback for a real phone pairing. Only synthetic tests substitute software keys.

At enrollment, the Mac obtains its existing vault KEK through the normal provider,
pins its check atomically, and wraps it using ephemeral P-256 ECDH, HKDF-SHA256 and
ChaCha20-Poly1305 for the phone/pairing. The phone persists only this encrypted
capsule and enclave-bound key handles, never a plaintext vault key. This explicitly
adds a second cryptographic unlock path to a passkey vault.

For each operation, the phone authenticates anew, unwraps its capsule, and signs
the complete command, reviewed request, pairing ID, and fresh Mac-generated
challenge. The encrypted channel carries the command and authorized key back to
the Mac. The Mac verifies device trust, the signature, expiry, vault key version
and current credential/request state before using a short-lived operation handle.
The Mac's normal provider is never replaced or kept unlocked by phone approval.
Swift/CryptoKit manage transient memory; zeroization of every copy is not promised.

The relay sees routing metadata, message lengths/timing and APNs registration;
it does not have E2E pairing keys, vault KEKs, or plaintext commands/responses.
Routing credentials and encryption keys are separate. Every phone channel uses
fresh challenge-bound, direction-bound authenticated encryption.

**Disconnect All Companions** revokes paired devices on the Mac and cancels
outstanding requests. The Mac saves revocation before cloud cleanup. If the relay
is unreachable, a stale generic alert may still arrive, but cannot authorize or
fetch a revoked vault. Startup reconciles relay registrations with saved trust.
The Mac reports Keychain persistence failures instead of claiming durable success.
Existing issued handles retain their TTL. A compromised full owner may already
have recovered keys; revocation cannot erase stolen keys or vault copies. Recovery
from such a compromise requires key rotation. A vault key migration invalidates
old phone capsules; pair again afterward.

## Notifications and links

Alert/sound permission, device-token registration, private APNs payloads, bounded
retry and expiration, and the **Review request** notification action are implemented.
The relay's APNs signing secrets and a signed physical-device build are still
required for live delivery. See [relay setup](../relay/README.md). Notifications
never approve directly; tapping authenticates and fetches current request state.
OS settings, Focus and Apple's best-effort delivery can delay or suppress alerts.

- Native route: `agentcreds://approve/<request UUID>`.
- HTTPS route: `https://agentcreds.vercel.app/approve/<request UUID>`.
- Neither link contains a redemption token, grant, or key.
- Mac URL handling requires the packaged app's scheme registration.

Both apps have `applinks:` entitlements. HTTPS opening additionally requires Apple
team signing and an AASA deployment on the approval-link domain. The example under
`AssociatedDomains` must be merged with the domain's existing passkey association.
The relay deployment does not deploy that separate domain or a web fallback.

## Validation and demo

Tap **Explore the demo**, or launch with `--demo`. It uses synthetic metadata,
discards entered values, never connects to a vault and does not enroll owner keys.
`--approval <URL>` can exercise an approval sheet in demo. Simulator builds use
`CODE_SIGNING_ALLOWED=NO`; independent owner enrollment requires a physical
Secure Enclave device.

`swift test` verifies encryption/tampering, signatures, expiry, one-time redemption,
revocation, immutable request review, vault migration, and local encrypted management.
The live relay test instructions are in [relay/README.md](../relay/README.md).
Live synthetic tests verify rotation of QR credentials, trusted pairing restoration,
and phone-authorized vault operations against the deployed relay without another
Mac key lookup. Physical Face ID, camera QR scanning, cellular/background APNs,
and signed Universal Links remain separate unverified checkpoints.

The paid hosted-vault version is [planned](../docs/product-tiers.md). The current
relay does not provide cloud vault storage, offline Mac execution or subscription
billing.
