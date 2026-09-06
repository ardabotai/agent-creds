# AgentCreds relay

Deployed endpoint: https://agentcreds-relay.agentcreds-relay.workers.dev

A Cloudflare Worker and SQLite-backed Durable Object route authenticated
WebSocket sessions between a Mac and paired iPhones. The Mac keeps the vault,
performs credential operations, and remains authoritative for approvals.
The relay never receives the end-to-end pairing key, vault KEK, or plaintext vault
commands/responses. It does see routing identifiers, message sizes/timing, and
APNs device tokens. This is the transport for the local-vault product, not the
paid hosted vault/execution service described in `../docs/product-tiers.md`.

## Development and deployment

```sh
cd relay
npm ci
npm run check
npm run dev
# In another terminal:
npm test
# Validate then deploy:
npx wrangler deploy --dry-run
npm run deploy
```

Wrangler is pinned locally to 4.129.0 because the previously cached 4.97.0 runtime
could not run this compatibility date. Authentication uses the existing Cloudflare
OAuth session. Always verify `npx wrangler whoami` before infrastructure changes.
The current account is on the Workers Free plan; no paid plan was enabled.

`RELAY_URL=https://agentcreds-relay.agentcreds-relay.workers.dev npm test` tests
the deployed API using temporary random room/device credentials, then deletes the
room. It never reads a real vault. To exercise the Swift end-to-end flow from the
repository root:

```sh
AGENTCREDS_TEST_RELAY_URL=https://agentcreds-relay.agentcreds-relay.workers.dev \
  swift test --filter TrustedDeviceTests/testTrustedPhoneManagesPasskeyVaultAndReleasesWithoutMacPrompt
```

That test uses a temporary synthetic passkey vault and software device keys,
rotates QR credentials, restores trusted pairing after a simulated restart, and
performs add/replace/edit/delete/approve/redeem without the Mac key provider being
available after enrollment. It does not prove physical Face ID or cellular delivery.

## Protocol and storage

- `PUT /v1/rooms/:room` registers an unguessable Mac routing credential. Its hash
  is stored in the room; subsequent setup calls must authenticate with that token.
- `GET /v1/rooms/:room/host` upgrades the Mac's outbound authenticated WebSocket.
- `PUT/DELETE /v1/rooms/:room/devices/:pairing` register/revoke phone routing
  credentials; only the Mac credential can call these operations.
- `GET /v1/rooms/:room/phone/:pairing` upgrades an authenticated phone connection.
  If the Mac is offline, the relay returns 503 instead of queueing vault operations.
- Each phone connection receives a fresh Mac-generated 32-byte challenge. Its
  single encrypted command and encrypted response are routed in an isolated
  channel. Reconnect discards in-flight challenges and does not retry commands.
- QR enrollment credentials expire after 10 minutes. Successful owner enrollment
  rotates both the relay token and E2E pairing key, and gives the phone a new
  encrypted invite valid for one year. The old QR code no longer works. Losing the
  enrollment response requires pairing again; it does not fall back to a weak path.
- Mac trust lives in one atomic, device-local Keychain item. It contains routing
  credentials, pairing keys and public signing keys, never a vault KEK. Pending
  approvals remain in memory and are invalidated by daemon restart.
- The relay stores token hashes, device expiry, notification registration and
  bounded notification jobs. WebSocket routing survives DO hibernation through
  attachments. It does not store command ciphertext or replay it later.

Limits: eight paired phones, sixteen simultaneous phone channels, bounded frame
and control-body sizes, phase enforcement, per-connection message rate limits,
and edge IP limits. New room registration also has a separate rate limit. This
first release uses capability-based QR enrollment rather than a public account
signup system. A paid product must add account enrollment, subscription checks,
per-tenant quotas and operational monitoring before broad distribution.

Headers carry routing credentials; never put them in URLs or logs. Worker
observability is disabled to avoid accidental payload/header collection. Operator
Cloudflare metrics remain available. Do not enable request-body logging or traces
that capture authorization headers, frames, notification payloads, or secrets.

## Apple push provisioning

The relay implements generic APNs alerts, expires them with each request, and
retries transient failures twice using the same collapse ID. Device tokens are
stored separately from the encrypted vault protocol and removed on device revoke.
Only the authenticated Mac can register device tokens or enqueue alerts.

Configure these Worker secrets via Wrangler's secure input (never CLI arguments):

- `APNS_TEAM_ID`
- `APNS_KEY_ID`
- `APNS_PRIVATE_KEY` (Apple APNs `.p8` key, not an App Store Connect API key)

The app topic is fixed to `ai.ardabot.agentcreds.companion`; Debug tokens use the
sandbox and Release tokens use production. An Apple-signed app with the matching
push entitlement is required. APNs signing secrets are not currently configured;
the Devices screen reports this explicitly. Apple delivery is best effort and
alerts do not themselves authorize a credential release.

## Operational boundaries

Revocation takes effect on the Mac before cloud cleanup. If cloud cleanup is
unavailable, a stale generic notification can still arrive, but cannot authorize
or fetch a revoked vault. Startup reconciles the relay device list with persisted
Mac trust. Keychain persistence failures surface to the Mac user rather than being
reported as durable revocation. Existing issued proxy handles retain their TTL.

Test separately on physical devices: QR scan over different networks, biometric
cancellation, background/locked phone alert delivery, Mac sleep/wake, network
switching, request expiry, device revoke, and daemon restart. The Mac must stay
online for the local-vault product. Native approval links work independently of
Universal Link domain deployment, which remains a separate provisioning step.
