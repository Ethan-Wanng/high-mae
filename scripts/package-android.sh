#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${WING_VERSION:-1.0.4.7.2}"
BUILD_NUMBER="${FLUTTER_BUILD_NUMBER:-4072}"
DIST="$ROOT/dist"
APK="$DIST/wing-${VERSION}-android-universal.apk"

if ! command -v flutter >/dev/null 2>&1; then
  echo "Flutter is required to build Android APKs." >&2
  exit 1
fi

mkdir -p "$DIST"

pushd "$ROOT/flutter_ui" >/dev/null
flutter pub get
flutter build apk --release --build-name "$VERSION" --build-number "$BUILD_NUMBER"
popd >/dev/null

cp "$ROOT/flutter_ui/build/app/outputs/flutter-apk/app-release.apk" "$APK"
echo "Android APK generated: $APK"
