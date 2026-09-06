# Free relay release candidate — 2026-09-06

Status: not approved for public release. Remaining Apple provisioning and real-device
checks must pass; signed artifacts alone are not release proof.

## Verified

- 59 Swift tests pass, plus the live synthetic trusted-device vault management and
  approval test against the deployed Cloudflare relay.
- Relay TypeScript checks and live isolation/replay/revocation test pass.
- Mac 1.1.0 universal arm64/x86_64 package built and signed with Developer ID.
  Artifact: `dist/agent-creds-1.1.0-macos-universal.zip` (local, not published).
- iOS 1.0.0 (1) signed archive succeeds. Development IPA export succeeds at
  `dist/ios-device/AgentCreds.ipa`. This is not a TestFlight release.
- Approval-link site source prepared in the separate `ardabotai/agentcreds-site`
  repository: preserve passkey association, add both app identifiers and a strict
  UUID-only fallback route. Production deployment `dpl_EdiRkoeP8oXNeEQFRk8vXtuR4dGJ` and HTTP checks pass, with no scripts,
  no-store, no-referrer, noindex and restrictive CSP.

## Release blockers

- APNs relay signing secrets remain absent. Supply an APNs key path, Key ID and
  Team ID through private local configuration; never commit or print the key.
- TestFlight export failed with “Error Downloading App Information”. Verify the
  App Store Connect app record for `ai.ardabot.agentcreds.companion` and account/API
  access, then export/upload and confirm processing and tester availability.
- Notarization has not run: no provided valid notarytool Keychain profile.
  Re-run `VERSION=1.1.0 KEYCHAIN_PROFILE=<profile> bash scripts/package.sh`, then
  verify Apple's acceptance and the stapled DMG before publishing.
- The paired physical iPhone is unavailable. Connect and unlock it, install the
  signed development package, and complete the device matrix below.
- Verify Apple's signed-device Universal Link handling. Production HTTP association
  and fallback are verified, but HTTP success alone is not device proof.

## Physical acceptance matrix

Use a temporary synthetic vault and a harmless test endpoint.

- Scan Mac QR with iPhone on cellular; confirm enrollment on Mac, then independently
  add, replace, edit policy and delete a test credential from iPhone.
- Request approval; receive an alert while phone is locked/backgrounded; tap to
  review, authenticate using Face ID, redeem once; reject second redemption.
- Cancel Face ID; deny notifications; deny a request; let a request expire. Confirm
  none releases credentials. Restore notification permission afterward.
- Switch networks and sleep/wake Mac during review and during mutation. Confirm
  reconnect, explicit unavailable status, no replay and refresh-before-retry.
- Restart Mac: trusted device reconnects, previous pending request is invalidated.
- Revoke phone: old links, routing credentials and signatures cannot regain access.
- Open HTTPS and native approval URLs from outside the app on both platforms.
- Verify iPad portrait/full-screen layout and clean Mac install/Gatekeeper launch.

Do not mark these physical checks passed based on software-key relay tests or
simulator demo UI. The Mac must remain online for the free local-vault product.
