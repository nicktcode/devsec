#!/usr/bin/env bash
#
# Rebuild damit from source and install into /Applications/Damit.app.
#
# Signs with your Apple Development identity so TCC (Full Disk Access,
# Automation) permission grants persist across rebuilds. Without a
# stable signing identity, every rebuild changes the code signature and
# macOS resets granted permissions.
#
# Usage:
#   ./scripts/deploy.sh
#
# Requires:
#   * An "Apple Development" or "Developer ID Application" code-signing
#     identity in your login keychain.
#   * /Applications/Damit.app already existing (first-time install is a
#     separate script).

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
APP="/Applications/Damit.app"
BUILD_DIR="$REPO/.build/arm64-apple-macosx/release"
SIGNING_IDENTITY_HINT="${DAMIT_SIGNING_IDENTITY:-Apple Development: Nick Thommen}"

cd "$REPO"

echo ">> building release…"
swift build -c release

if [ ! -d "$APP" ]; then
    echo "!! $APP does not exist. Run the first-install script or copy the"
    echo "   bundle manually before using this deploy script."
    exit 1
fi

echo ">> installing binary"
cp "$BUILD_DIR/DevsecApp" "$APP/Contents/MacOS/DevsecApp"

echo ">> installing SPM resource bundle"
rm -rf "$APP/Contents/Resources/damit_DevsecApp.bundle"
cp -R "$BUILD_DIR/damit_DevsecApp.bundle" "$APP/Contents/Resources/damit_DevsecApp.bundle"

# Locate the signing identity by substring match so the script works
# regardless of your team's specific certificate ID.
IDENTITY_HASH="$(
    security find-identity -p codesigning -v \
    | grep -F "$SIGNING_IDENTITY_HINT" \
    | head -n1 \
    | awk '{print $2}' \
    || true
)"

if [ -z "$IDENTITY_HASH" ]; then
    echo "!! No code-signing identity matching '$SIGNING_IDENTITY_HINT' found."
    echo "   Falling back to ad-hoc signing. TCC permissions WILL reset on"
    echo "   the next rebuild. Fix by setting DAMIT_SIGNING_IDENTITY to any"
    echo "   substring that matches an identity in 'security find-identity"
    echo "   -p codesigning -v'."
    codesign --force --deep --sign - "$APP"
else
    echo ">> signing with $IDENTITY_HASH"
    codesign --force --deep --sign "$IDENTITY_HASH" "$APP"
fi

echo ">> relaunching"
pkill -x DevsecApp 2>/dev/null || true
sleep 1
open "$APP"

echo ">> deployed."
codesign -dv "$APP" 2>&1 | grep -E "Authority|Identifier|TeamIdentifier" | head -3
