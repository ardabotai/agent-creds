# Changelog

## 1.0.0

First release. A macOS secret store where agents can use credentials without
ever seeing them.

### Agent surfaces
- MCP server with `list_secrets`, `save_secret`, `request_secret`,
  `begin_signup`, `capture_secret`, `fill_browser_field`
- Local egress proxy (`/p/<host>/<path>`) with a `{{acred:*}}` placeholder DSL,
  usable from any HTTP client
- `agentcreds run --with <secret> -- <cmd>` for CLI tools
- Browser fill over the Chrome DevTools Protocol for Playwright / agent-browser
- Account signup with generated passwords the agent never sees

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
