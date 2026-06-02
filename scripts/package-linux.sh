#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${WING_VERSION:-1.0.0}"
TAGS="with_quic,with_utls,with_gvisor,with_naive_outbound,with_purego"
DIST="$ROOT/dist"
WORK="$DIST/linux-package"
PAYLOAD="$WORK/payload"
ARCHIVE="$WORK/wing-linux-payload.tar.gz"
INSTALLER="$DIST/wing-${VERSION}-linux-x64.run"

rm -rf "$WORK"
mkdir -p "$PAYLOAD" "$DIST"

echo "Building wing Linux backend..."
(cd "$ROOT" && go build -tags "$TAGS" -ldflags "-s -w" -o "$PAYLOAD/wing" .)
chmod +x "$PAYLOAD/wing"

cat > "$PAYLOAD/README.txt" <<EOF
wing ${VERSION}

Run ./wing to start the local backend and tray. If the desktop UI bundle is not
present, wing opens http://127.0.0.1:10809/ in your default browser.
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

cat > "$HOME/.local/share/applications/wing.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=wing
Comment=Desktop proxy client backend
Exec=$INSTALL_DIR/wing
Terminal=false
Categories=Network;
DESKTOP

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
