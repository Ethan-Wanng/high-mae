#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${WING_VERSION:-1.0.4.1}"
ARCH="${WING_ARCH:-$(uname -m)}"
case "$ARCH" in
  x86_64|amd64) DIST_ARCH="x64" ;;
  aarch64|arm64) DIST_ARCH="arm64" ;;
  *) DIST_ARCH="$ARCH" ;;
esac
TAGS="with_quic,with_utls,with_gvisor,with_naive_outbound,with_purego"
DIST="$ROOT/dist"
WORK="$DIST/linux-package"
PAYLOAD="$WORK/payload"
ARCHIVE="$WORK/wing-linux-payload.tar.gz"
INSTALLER="$DIST/wing-${VERSION}-linux-${DIST_ARCH}.run"

rm -rf "$WORK"
mkdir -p "$PAYLOAD" "$DIST"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "Linux packages must be built on Linux." >&2
  exit 1
fi

echo "Building wing Linux backend (${DIST_ARCH})..."
(cd "$ROOT" && go build -tags "$TAGS" -ldflags "-s -w" -o "$PAYLOAD/wing" .)
chmod +x "$PAYLOAD/wing"

cat > "$PAYLOAD/README.txt" <<EOF
wing ${VERSION}

Run ./wing to start the local backend and tray. The local control panel runs at
http://127.0.0.1:10809/ and opens in the default browser when no Flutter desktop
bundle is present for this platform.
EOF

cat > "$PAYLOAD/wing.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=wing
Comment=Desktop proxy client
Exec=__INSTALL_DIR__/wing
Terminal=false
Categories=Network;
EOF

tar -czf "$ARCHIVE" -C "$PAYLOAD" .

cat > "$INSTALLER" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

DEFAULT_DIR="${HOME}/.local/share/wing"
printf "wing installer\n\n"
printf "Install directory [%s]: " "$DEFAULT_DIR"
read -r INSTALL_DIR
INSTALL_DIR="${INSTALL_DIR:-$DEFAULT_DIR}"

mkdir -p "$INSTALL_DIR"
ARCHIVE_LINE="$(awk '/^__WING_ARCHIVE_BELOW__/ { print NR + 1; exit 0; }' "$0")"
tail -n +"$ARCHIVE_LINE" "$0" | tar -xz -C "$INSTALL_DIR"
chmod +x "$INSTALL_DIR/wing"

mkdir -p "$HOME/.local/bin" "$HOME/.local/share/applications"
ln -sf "$INSTALL_DIR/wing" "$HOME/.local/bin/wing"
sed "s#__INSTALL_DIR__#$INSTALL_DIR#g" "$INSTALL_DIR/wing.desktop" > "$HOME/.local/share/applications/wing.desktop"

if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "$HOME/.local/share/applications" >/dev/null 2>&1 || true
fi

printf "\nwing installed to %s\n" "$INSTALL_DIR"
printf "Run: %s/wing\n" "$INSTALL_DIR"
printf "Control panel: http://127.0.0.1:10809/\n"

printf "\nStart wing now? [Y/n]: "
read -r START_NOW
case "${START_NOW:-Y}" in
  y|Y|yes|YES)
    nohup "$INSTALL_DIR/wing" >/dev/null 2>&1 &
    ;;
esac
exit 0
__WING_ARCHIVE_BELOW__
EOF

cat "$ARCHIVE" >> "$INSTALLER"
chmod +x "$INSTALLER"

echo "Linux installer generated: $INSTALLER"
