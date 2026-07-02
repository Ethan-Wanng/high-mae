#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${WING_VERSION:-1.0.5.2}"
ARCH="${WING_ARCH:-$(uname -m)}"
case "$ARCH" in
  x86_64|amd64) DIST_ARCH="x64" ;;
  arm64|aarch64) DIST_ARCH="arm64" ;;
  *) DIST_ARCH="$ARCH" ;;
esac
TAGS="with_quic,with_utls,with_gvisor,with_naive_outbound,with_purego"
LDFLAGS="-s -w"
if [[ -n "${WING_FREE_FLOW_NODE_LINK:-}" ]]; then
  LDFLAGS="$LDFLAGS -X wing/pkg/freeflow.packagedNodeLink=${WING_FREE_FLOW_NODE_LINK}"
fi
DIST="$ROOT/dist"
WORK="$DIST/macos-package"
APP="$WORK/root/Applications/wing.app"
CONTENTS="$APP/Contents"
MACOS="$CONTENTS/MacOS"
RESOURCES="$CONTENTS/Resources"
PKG="$DIST/wing-${VERSION}-macos-${DIST_ARCH}.pkg"

rm -rf "$WORK"
mkdir -p "$MACOS" "$RESOURCES" "$DIST"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "macOS packages must be built on macOS." >&2
  exit 1
fi

echo "Building wing macOS app (${DIST_ARCH})..."
(cd "$ROOT" && go build -tags "$TAGS" -ldflags "$LDFLAGS" -o "$MACOS/wing" .)
chmod +x "$MACOS/wing"

if [[ -f "$ROOT/assets/icon.ico" ]]; then
  cp "$ROOT/assets/icon.ico" "$RESOURCES/icon.ico"
fi

cat > "$CONTENTS/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDisplayName</key>
  <string>wing</string>
  <key>CFBundleExecutable</key>
  <string>wing</string>
  <key>CFBundleIdentifier</key>
  <string>com.ethanwang.wing</string>
  <key>CFBundleName</key>
  <string>wing</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleIconFile</key>
  <string>icon.ico</string>
  <key>CFBundleShortVersionString</key>
  <string>${VERSION}</string>
  <key>CFBundleVersion</key>
  <string>${VERSION}</string>
  <key>LSMinimumSystemVersion</key>
  <string>11.0</string>
</dict>
</plist>
EOF

pkgbuild \
  --root "$WORK/root" \
  --install-location "/" \
  --identifier "com.ethanwang.wing" \
  --version "$VERSION" \
  "$PKG"

echo "macOS installer generated: $PKG"
