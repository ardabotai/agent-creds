# Security Policy

agent-creds holds credentials, so security reports get priority over everything
else in this repo.

## Reporting a vulnerability

**Do not open a public issue for a security bug.**

Use GitHub's private vulnerability reporting: go to the **Security** tab →
**Report a vulnerability**. That opens a private channel visible only to
maintainers.

Please include the version or commit, your macOS version, what an attacker can
achieve, and the steps to reproduce it. A proof of concept helps a lot.

Expect an acknowledgement within a few days. We will confirm the issue, agree a
disclosure timeline with you, and credit you in the release notes unless you
prefer otherwise.

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | ✅ |
| < 1.0 | ❌ |

## What counts as a vulnerability

The security model is: **an agent can ask for a credential and nothing more.**
Anything that breaks one of these is in scope:

- A stored secret's plaintext reaching an agent's context by any path
- Releasing a credential without the human ceremony, or faking/replaying it
- Sending a credential to a host outside the secret's allowlist (including via
  redirects, DNS tricks, or `Host` confusion)
- Escaping the placeholder DSL to inject arbitrary values into a request
- Reading the vault, audit log, or master key from another local user account
- A prompt-injected agent escalating beyond "ask" — for example steering a
  browser fill or an egress request to a destination the user did not approve

## Known limitations (not vulnerabilities)

These are documented design boundaries in v1, not bugs. They are on the roadmap:

- **The biometric gate is procedural**, enforced by the app rather than bound to
  the crypto. A root-level compromise of the machine defeats it. Phase 3's
  passkey + WebAuthn PRF work makes the ceremony derive the unwrap key itself.
- **Agent identity is attribution, not a boundary.** Client names are
  self-reported; any local process running as the user can connect to the socket
  and claim any name. Pairing tokens are a v1.1 item. The security boundary is
  the ceremony, not the caller's identity.
- **The CLI reads the vault directly**, so local tooling running as the user can
  bypass the daemon for CLI-initiated reads.
- **Secrets exist in memory** in the daemon and, for `agentcreds run`, in the
  child process environment. Every local vault has this property.
- **`AGENTCREDS_DEV_KEK_FILE=1`** deliberately stores the master key in a file
  instead of the Keychain. It is a development affordance and is documented as
  unsafe for real use.
