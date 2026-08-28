# Contributing

Thanks for your interest. This is a security tool, so the bar for changes to
the release paths is deliberately high — but small fixes and docs are very
welcome.

## Getting started

Requires macOS 14+ and a Swift 5.9+ toolchain (Xcode 15+).

```sh
swift build
swift test
```

To run the daemon from a dev build without the Keychain re-prompting on every
rebuild (unsigned binaries get a new code identity each time):

```sh
AGENTCREDS_DEV_KEK_FILE=1 .build/debug/agentcredsd
```

That flag stores the master key in a `0600` file instead of the Keychain. It is
for development only — never use it on a machine holding real secrets.

## The invariant

Every change is measured against one rule:

> An agent can ask for a credential. It can never see one, and it can never
> approve its own request.

If a change puts a secret value on a path an agent can observe, or lets anything
other than the human ceremony authorize a release, it will not be merged in that
form. Concretely:

- Never return a raw secret from an MCP tool
- Never make approval depend on data the agent controls
- Never widen a host allowlist implicitly (empty means deny, everywhere)
- Anything injected into a request must be added to the scrub list, in every
  form it takes on the wire

## Releases

`scripts/package.sh` builds universal binaries, signs them with a Developer ID,
and notarizes the tarball. Signing is not cosmetic here: an unsigned binary gets
a new code identity on every build, which invalidates the Keychain ACL on the
master key and makes macOS re-prompt on every update.

```sh
KEYCHAIN_PROFILE=notary ./scripts/package.sh
```

The Developer ID identity is auto-detected; set `SIGN_ID` to override. Create
the notary profile once:

```sh
xcrun notarytool store-credentials notary \
  --apple-id <your-apple-id> --team-id 3CQT7X643L --password <app-specific-password>
```

Without `KEYCHAIN_PROFILE` the script signs but skips notarization, which is
fine for local testing and not fine for anything users download.

## Pull requests

- Add tests for behavior changes. Security-relevant logic — host matching, the
  placeholder DSL, scrubbing, approval flow — needs tests that fail without the
  fix.
- Keep `swift test` green.
- Match the surrounding style: comments explain *why*, not *what*.
- Note any change to the security model in the PR description, and update
  `SECURITY.md` if it moves a documented boundary.

For a security vulnerability, do not open a PR or issue — see
[SECURITY.md](SECURITY.md).
