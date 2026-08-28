# agent-creds

**v1.0.0 · macOS 14+**

An AI-first secret store. Agents can save, request, and *use* credentials over
MCP — but **an agent never sees a stored secret**. Every release is a human
ceremony (Touch ID), and what an agent gets back is a short-lived handle, not
the credential.

```
agent ──MCP──▶ agentcredsd ──Touch ID──▶ you
                    │
                    ├─▶ egress proxy   real credential attached at send time
                    ├─▶ env injection  child process only
                    └─▶ browser fill   typed into the page over CDP
```

## Why it works this way

An agent can be prompt-injected by anything it reads, so it is treated as an
untrusted client. Connecting to the MCP server grants the ability to *ask* and
nothing more:

1. **Approval never passes through the agent.** The Touch ID prompt is the
   daemon's own UI, so a hijacked agent cannot capture, replay, or fake it.
2. **The agent never holds the value.** It gets an opaque `acred_*` handle; the
   daemon attaches the real credential at egress, injects it into a child
   process, or types it into a page itself.
3. **Allowed hosts are mandatory, and empty means deny.** A secret carries the
   hosts it may be used against. There is deliberately no allow-all.
4. **Everything is scrubbed and logged.** Injected values are redacted from
   responses (byte-level, so binary bodies are covered), and every approval,
   denial, and release lands in an append-only audit log.

## Install

Requires macOS 14+ and a Swift 5.9+ toolchain (Xcode 15+).

```sh
git clone https://github.com/ArdaBot/agent-creds.git
cd agent-creds
./install.sh
```

Builds release binaries into `~/.local/bin`, registers the daemon as a login
agent, and starts it — the 🔑 menubar icon appears. Then:

```sh
agentcreds identity --email you@example.com
agentcreds add github/token --host api.github.com
claude mcp add agentcreds -- ~/.local/bin/agentcreds mcp --client claude-code
```

`./uninstall.sh` removes the binaries and login agent, leaving the vault intact.

## What an agent can do

| Tool | What happens |
|---|---|
| `list_secrets` | Names and kinds only — never values |
| `save_secret` | Stores a secret (Touch ID); requires `allowed_hosts` |
| `request_secret` | Touch ID → returns a short-lived proxy handle |
| `begin_signup` | Touch ID → signs the user up with a **generated** password |
| `capture_secret` | Opens a secure paste window for a secret not yet in the vault |
| `fill_browser_field` | Touch ID → daemon types the secret into a page over CDP |

## Agent surfaces

Every surface has a path where the value flows daemon → destination, never
through the agent:

| Surface | Mechanism |
|---|---|
| HTTP APIs (any client, incl. `curl`) | egress proxy handle + placeholder DSL |
| CLI tools (`gh`, `aws`, …) | `agentcreds run --with <secret> -- <cmd>` |
| Browser automation (Playwright, agent-browser, any Chromium with `--remote-debugging-port`) | `fill_browser_field` over CDP |
| Signup anywhere | `begin_signup` + generated passwords |

## The egress proxy and the placeholder DSL

Handles are used against a local rewriting gateway (not a CONNECT proxy — TLS
would hide request bodies from it):

```
METHOD http://127.0.0.1:9977/p/<host>/<path>
Authorization: Bearer acred_...
```

The daemon enforces expiry and the host allowlist, re-checks every redirect hop
against that allowlist, substitutes placeholders, attaches the credential using
the secret's own injection scheme (`bearer`, a custom header like `X-Api-Key`,
or `basic`), forwards over HTTPS, and scrubs injected values from the response.

| Placeholder | Substituted with |
|---|---|
| `{{acred:password.generate}}` | Generated password (stable within the grant; signup grants only) |
| `{{acred:password.generate:tag}}` | A second, independent generated password |
| `{{acred:password.confirm}}` | Same value again, for confirm fields |
| `{{acred:email}}` / `{{acred:username}}` | The configured identity |

On a successful signup response the generated password is saved to the vault as
`<service>/password` — and only marked saved once that write is durable, so a
failure retries rather than losing the only copy of a live account password.

## Secure intake

Secrets enter the vault without ever transiting an agent's context:

- **`capture_secret`** opens a window with a secure password field. Apple
  Passwords AutoFill works in it directly (system Touch ID gate); users on other
  managers copy-paste into the same field.
- **`agentcreds add`** takes it on the CLI with hidden input.

## Command reference

```sh
agentcreds mcp --client <name>              # MCP stdio shim (used by agent hosts)
agentcreds add <name> --host <host> …       # store a secret (--host required)
   [--kind opaque|oauthRefresh|awsRoot|githubApp]
   [--header X-Api-Key [--header-prefix "token "]] [--basic-user <user>]
agentcreds ls                               # list names and kinds
agentcreds rm <name>
agentcreds identity [--email …] [--username …]
agentcreds audit [--limit N]                # approval / release history
agentcreds run --with <name>[:ENV_VAR] … -- <cmd> [args…]
```

## Crypto and storage

Envelope encryption: each secret gets its own DEK (ChaCha20-Poly1305 via
CryptoKit), wrapped by a master KEK held in the Keychain. Rotating the KEK only
re-wraps DEKs, never re-encrypts values. Vault, audit log, and identity live in
`~/Library/Application Support/agent-creds`, created `0600` before any bytes are
written.

## Layout

- `Sources/AgentCredsCore` — models, envelope crypto, vault, minters, host
  policy, placeholder DSL, audit log, approval ceremony
- `Sources/agentcredsd` — menubar daemon: MCP server, egress proxy, capture
  window, browser filler
- `Sources/agentcreds` — CLI and MCP stdio shim

## Known limitations (v1)

- **The biometric gate is procedural**, enforced by the app rather than bound to
  the crypto. Phase 3's passkey + WebAuthn PRF upgrade makes the ceremony derive
  the unwrap key itself.
- **Agent identity is attribution, not a boundary.** Client names are
  self-reported (pairing tokens are a v1.1 item). On a single-user Mac the real
  boundary was always the ceremony, not the caller's identity.
- **The CLI reads the vault directly**, so local tooling can bypass the daemon's
  ceremony for CLI-initiated reads.
- **Mac-only.** iPhone approval, iCloud Keychain sync, and CloudKit are Phase 2
  and need a signed, provisioned app bundle.
- **Unsigned dev builds** re-prompt for Keychain access on every rebuild; export
  `AGENTCREDS_DEV_KEK_FILE=1` to keep the KEK in a `0600` file instead. Never
  use that outside development.

## Roadmap

- **v1.1** — agent pairing tokens with per-agent revocation; bulk CSV import
- **Phase 2** — signed bundle, iCloud Keychain KEK, CloudKit sync, iPhone
  push-to-approve with Face ID
- **Phase 3** — passkey + PRF crypto-gated ceremonies; provider-native minters
  (STS sessions, OAuth access tokens, GitHub App installation tokens)

## Contributing

Issues and pull requests are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md)
for the development setup and the one invariant every change is measured
against. Participation is governed by our
[Code of Conduct](CODE_OF_CONDUCT.md).

**Found a security bug?** Do not open a public issue — follow
[SECURITY.md](SECURITY.md), which also documents the threat model and the
boundaries that are known limitations rather than vulnerabilities.

## License

MIT — see [LICENSE](LICENSE). Copyright © 2026 ArdaBot, Inc.
