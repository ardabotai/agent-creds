#!/bin/bash
# Builds, signs, and notarizes a release tarball.
#
# Signing matters here beyond looking professional: an unsigned binary gets a
# new code identity on every build, which invalidates the Keychain ACL on the
# master key and makes macOS re-prompt the user constantly. A stable Developer
# ID signature means they authorize once.
#
# Required environment:
#   SIGN_ID     "Developer ID Application: ArdaBot, Inc. (TEAMID)"
#   KEYCHAIN_PROFILE   notarytool profile name, created once with:
#       xcrun notarytool store-credentials <profile> \
#         --apple-id <you@example.com> --team-id <TEAMID> --password <app-specific-password>
set -euo pipefail

VERSION="${VERSION:-$(git describe --tags --always)}"
DIST="dist"
STAGE="$DIST/agent-creds-$VERSION"

: "${SIGN_ID:?set SIGN_ID to your Developer ID Application identity}"

echo "==> Building universal binaries ($VERSION)"
swift build -c release --arch arm64 --arch x86_64

rm -rf "$STAGE" && mkdir -p "$STAGE"
cp .build/apple/Products/Release/agentcreds "$STAGE/"
cp .build/apple/Products/Release/agentcredsd "$STAGE/"
cp install.sh uninstall.sh README.md LICENSE "$STAGE/"

echo "==> Signing with hardened runtime"
for bin in agentcreds agentcredsd; do
  codesign --force --timestamp --options runtime \
           --sign "$SIGN_ID" "$STAGE/$bin"
  codesign --verify --strict --verbose=2 "$STAGE/$bin"
done

TARBALL="$DIST/agent-creds-$VERSION-macos-universal.tar.gz"
echo "==> Packaging $TARBALL"
tar -czf "$TARBALL" -C "$DIST" "agent-creds-$VERSION"

if [ -n "${KEYCHAIN_PROFILE:-}" ]; then
  echo "==> Notarizing (this waits for Apple)"
  xcrun notarytool submit "$TARBALL" --keychain-profile "$KEYCHAIN_PROFILE" --wait
  # A tarball cannot be stapled; the binaries inside are notarized and Gatekeeper
  # verifies them online. Ship a .dmg or .pkg later if offline stapling matters.
  echo "==> Notarized. Verifying one binary:"
  spctl --assess --type execute --verbose "$STAGE/agentcreds" || true
else
  echo "==> KEYCHAIN_PROFILE not set — skipping notarization (binaries are signed only)"
fi

shasum -a 256 "$TARBALL" | tee "$TARBALL.sha256"
echo
echo "Done: $TARBALL"
echo "Use the sha256 above in the Homebrew formula."
