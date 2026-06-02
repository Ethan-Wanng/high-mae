#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${WING_VERSION:-1.0.0}"
TAGS="with_quic,with_utls,with_gvisor,with_naive_outbound,with_purego"
DIST="$ROOT/dist"
WORK="$DIST/macos-package"
APP="$WORK/root/Applications/wing.app"
CONTENTS="$APP/Contents"
MACOS="$CONTENTS/MacOS"
RESOURCES="$CONTENTS/Resources"
PKG="$DIST/wing-${VERSION}-macos-x64.pkg"

rm -rf "$WORK"
mkdir -p "$MACOS" "$RESOURCES" "$DIST"

echo "Building wing macOS backend..."
(cd "$ROOT" && go build -tags "$TAGS" -ldflags "-s -w" -o "$MACOS/wing" .)
chmod +x "$MACOS/wing"

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
