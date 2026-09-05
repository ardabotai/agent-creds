# Changelog

## Unreleased

### Added — Mac app UI (v1)
- Polished menubar: vault status, secrets list (names/kinds/hosts only), identity,
  recent audit, doctor/setup shortcuts, passkey protect, and quit.
- Lightweight management window (SwiftUI): list/add/remove secrets (hosts
  required), identity editor, passkey status/enroll, and audit browser.
- Secret values never appear in list/UI surfaces — only the secure Add Secret
  field accepts plaintext, matching the existing capture dialog invariant.
- `SecretMetadata` now includes `allowedHosts` for UI/CLI listing (still no values).

### Added — Phase 3: passkey-derived vault key
- The vault KEK can now be derived from a WebAuthn passkey's PRF output rather
  than stored in the Keychain. The assertion *is* the key release: without a
  Touch ID approval the key does not exist in the process, so an unapproved
  release is impossible rather than merely refused.
- `agentcreds passkey status|enroll`, and a menubar item, move an existing vault
  across. Enrollment re-wraps every DEK before switching and only then removes
  the Keychain copy, so a failure leaves the vault exactly as it was.
- The daemon ships as a signed `.app` bundle carrying the
  `associated-domains` entitlement that passkeys require.

Passkey mode needs the signed build: entitlements cannot be attached to a bare
executable, so a local `swift build` stays on the Keychain KEK.

## 1.0.2

### Fixed
- `install.sh` shipped inside the release archive tried to compile source that
  is not in the archive. It now uses the signed binaries packaged beside it, and
  only builds when run from a git checkout — where it also reports a missing
  Swift toolchain instead of failing obscurely.

## 1.0.1

### Fixed
- A second daemon could unlink a socket another daemon was actively listening
  on. The original kept its listening file descriptor and the path still looked
  like a healthy socket, but every client got `ECONNREFUSED` — with the daemon
  alive, `lsof` showing it holding the socket, and the log saying "listening".
  A listener now refuses to displace one that answers, and a socket left by a
  crashed daemon is still reclaimed.
- `scripts/package.sh` produced a `.tar.gz`, which the Apple notary service
  rejects; it now builds a `.zip` with `ditto` so signatures survive, and no
  longer prints a misleading `spctl` rejection for bare executables.

## 1.0.0

First release. A macOS secret store where agents can use credentials without
ever seeing them. Maintained by ArdaBot, Inc.

### Agent surfaces
- MCP server with `list_secrets`, `save_secret`, `request_secret`,
  `begin_signup`, `capture_secret`, `fill_browser_field`
- Local egress proxy (`/p/<host>/<path>`) with a `{{acred:*}}` placeholder DSL,
  usable from any HTTP client
- `agentcreds run --with <secret> -- <cmd>` for CLI tools
- Browser fill over the Chrome DevTools Protocol for Playwright / agent-browser
- Account signup with generated passwords the agent never sees

### Setup
- `agentcreds setup` auto-detects Claude Code, Codex, opencode, and Cursor and
  registers the MCP server with each
- Agent skill teaching hosts when to reach for the vault, and never to ask for a
  secret in chat; `agentcreds skill` prints it for AGENTS.md-based hosts
- `agentcreds doctor` verifies daemon, proxy, registration, identity, and vault
- The MCP shim starts the daemon on demand, so the first agent call works on a
  fresh install

### Security
- Touch ID ceremony on the daemon's own UI for every release — never through
  the agent's conversation
- Allowed hosts are mandatory; an empty allowlist denies every host
- Injected values scrubbed from responses byte-level, in both raw and
  on-the-wire forms
- Redirects re-checked against the allowlist before the credential is re-sent
- CDP endpoints host-resolved, not prefix-matched
- Browser page re-verified after approval, so a navigation race cannot redirect
  a fill to another origin
- Per-secret injection scheme (`bearer`, custom header, `basic`)
- Envelope encryption; vault, audit log, and KEK files created 0600 inside a
  0700 directory before any bytes are written
- Append-only audit log of every approval, denial, and release
