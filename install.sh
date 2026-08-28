#!/bin/bash
# agent-creds installer: builds release binaries, installs them, and registers
# the daemon as a login agent. No sudo required — everything lands under $HOME.
set -euo pipefail

PREFIX="${PREFIX:-$HOME/.local/bin}"
LABEL="com.ardabot.agentcreds.daemon"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Building release binaries"
cd "$SOURCE_DIR"
swift build -c release

echo "==> Installing to $PREFIX"
mkdir -p "$PREFIX"
install -m 755 .build/release/agentcreds "$PREFIX/agentcreds"
install -m 755 .build/release/agentcredsd "$PREFIX/agentcredsd"

echo "==> Registering login agent ($LABEL)"
mkdir -p "$HOME/Library/LaunchAgents"
cat > "$PLIST" <<PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>$PREFIX/agentcredsd</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>$HOME/Library/Logs/agent-creds.log</string>
    <key>StandardOutPath</key>
    <string>$HOME/Library/Logs/agent-creds.log</string>
</dict>
</plist>
PLIST_EOF

launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"

echo
echo "Installed. The 🔑 menubar icon should be visible now."
echo
case ":$PATH:" in
  *":$PREFIX:"*) ;;
  *) echo "NOTE: $PREFIX is not on your PATH — add it to your shell profile."; echo ;;
esac
echo "Next steps:"
echo "  agentcreds identity --email you@example.com"
echo "  agentcreds add github/token --host api.github.com"
echo "  claude mcp add agentcreds -- $PREFIX/agentcreds mcp --client claude-code"
echo
echo "Logs: ~/Library/Logs/agent-creds.log"
echo "Uninstall: ./uninstall.sh"
