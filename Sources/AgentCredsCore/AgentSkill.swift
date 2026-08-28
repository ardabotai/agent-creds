import Foundation

/// The behavioral policy handed to agent hosts as a skill.
///
/// MCP tool descriptions tell an agent *how* to call a tool; they do not
/// reliably tell it *when* to reach for one. This is what stops an agent from
/// asking "paste your API key here" in chat — so it is shipped and installed
/// alongside the server rather than left to documentation.
public enum AgentSkill {
    public static let name = "agent-creds"

    /// Installed to ~/.claude/skills/agent-creds/SKILL.md by `agentcreds setup`.
    public static let markdown = #"""
---
name: agent-creds
description: Use whenever a task needs a credential — a password, API key, token, or login — including when a request fails with 401/403, a CLI tool needs auth, a site needs signing in, or a new account needs creating. The user's secrets live in agent-creds; you request temporary, user-approved credentials and use them WITHOUT ever seeing the value. Never ask the user to paste a secret into the conversation.
---

# agent-creds

The user keeps their credentials in agent-creds. You can use them, but you can
never see them. Every release is approved by the user with Touch ID.

## The one rule

**Never ask the user to paste a secret into the chat.** Not an API key, not a
password, not a token. If you need one, use `capture_secret` — it opens a
secure window where the user types it directly into the vault, and you get back
a handle instead of the value. A secret pasted into a conversation is
permanently exposed in the transcript; a captured one never touches your
context.

## When you need a credential

**Call `use_credential` and let the vault sort it out.** Pass the site you are
working with and an honest purpose:

```
use_credential(for: "github.com", purpose: "push the v1.2 release tag")
```

You do not need to know whether the user already has it. The vault checks:

- **It has one** → the user gets a dialog naming you, the credential, your
  stated purpose, and a duration to choose. Approving releases it.
- **It does not** → the user gets a secure window to provide it, and it is
  saved for next time.

Either way you get the same handle back, and never the value. `list_secrets`
shows what exists if you want to look first, but you do not have to.

The handle looks like this — never a value:

```json
{"payload":{"proxyHandle":{"proxyURL":"http://127.0.0.1:9977","token":"acred_9f2c..."}},
 "expiresAt":"2026-08-28T14:20:00Z","allowedHosts":["api.github.com"]}
```

## Using the handle

### HTTP requests — route through the proxy

Send to `<proxyURL>/p/<host>/<path>` with the handle as the bearer token. The
daemon swaps in the real credential at egress and scrubs it from the response.

```sh
curl -s http://127.0.0.1:9977/p/api.github.com/user \
  -H "Authorization: Bearer acred_9f2c..."
```

That is the *whole* pattern: replace `https://api.github.com` with
`http://127.0.0.1:9977/p/api.github.com` and send the handle. Works from any
HTTP client, any language.

### CLI tools — use `agentcreds run`

```sh
agentcreds run --with github/token -- gh pr create --fill
```

The user approves with Touch ID, then the secret is injected into that command's
environment only (`github/token` becomes `$GITHUB_TOKEN`; override with
`--with github/token:GH_TOKEN`). You never hold the value.

### Browsers — let the daemon type it

When automating a browser (Playwright, agent-browser, any Chromium started with
`--remote-debugging-port=9222`): navigate to the login page yourself, then call
`fill_browser_field(name, selector, purpose)`. The daemon connects over CDP and
fills the field. Submit the form afterward. Never read the field's value back.

### Creating an account — let the vault pick the password

Call `begin_signup(service, purpose)`, then send the site's signup request
through the proxy using placeholders where values belong:

```json
{"email":"{{acred:email}}",
 "password":"{{acred:password.generate}}",
 "password_confirmation":"{{acred:password.confirm}}"}
```

A strong password is generated at egress, saved to the user's vault on success,
and scrubbed from the response. You never see it. Placeholders `{{acred:email}}`
and `{{acred:username}}` also work on ordinary requests.

## Rules that will trip you up

- **`allowed_hosts` is required** when saving or capturing. A secret with no
  hosts has no egress path — it cannot be used anywhere. Pass the API host,
  e.g. `["api.github.com"]`.
- **Purpose strings are shown to the user, verbatim.** Write the real reason
  ("push the v1.2 release tag"), not a placeholder. The user decides based on it.
- **Handles expire** (15 min by default) and are scoped to their hosts. Requests
  to any other host fail closed. Request again rather than reusing an expired one.
- **A denial is final for that request.** If the user denies, tell them plainly
  what you were trying to do and stop. Do not retry the same request or try
  another route to the same secret.

## What to tell the user

When a tool is blocking on approval, say so: "I've requested access to your
GitHub token — approve the Touch ID prompt and I'll continue." When you save
something, name it: "Saved as `stripe/api-key`, scoped to api.stripe.com."
"""#
}
