#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT="$ROOT/flutter_ui/ios/Frameworks/WingCore.xcframework"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "The iOS core must be built on macOS." >&2
  exit 1
fi
command -v gomobile >/dev/null 2>&1 || {
  echo "gomobile is required: go install golang.org/x/mobile/cmd/gomobile@latest" >&2
  exit 1
}

mkdir -p "$(dirname "$OUTPUT")"
rm -rf "$OUTPUT"
pushd "$ROOT" >/dev/null
gomobile init
gomobile bind -target=ios -iosversion=15.0 -o "$OUTPUT" ./mobile/iosbridge
popd >/dev/null
echo "Generated $OUTPUT"
