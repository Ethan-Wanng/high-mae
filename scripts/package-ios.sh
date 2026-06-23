#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${WING_VERSION:-1.0.4.7.3}"
BUILD_NUMBER="${FLUTTER_BUILD_NUMBER:-4073}"
DIST="$ROOT/dist"
UNSIGNED_IPA="$DIST/wing-${VERSION}-ios-unsigned.ipa"
SIGNED_IPA="$DIST/wing-${VERSION}-ios.ipa"
EXPORT_OPTIONS_PLIST="${IOS_EXPORT_OPTIONS_PLIST:-}"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "iOS packages must be built on macOS with Xcode installed." >&2
  exit 1
fi

if ! command -v flutter >/dev/null 2>&1; then
  echo "Flutter is required to build iOS packages." >&2
  exit 1
fi

mkdir -p "$DIST"

pushd "$ROOT/flutter_ui" >/dev/null
flutter pub get

if [[ -n "$EXPORT_OPTIONS_PLIST" ]]; then
  if [[ ! -f "$EXPORT_OPTIONS_PLIST" ]]; then
    echo "IOS_EXPORT_OPTIONS_PLIST does not exist: $EXPORT_OPTIONS_PLIST" >&2
    exit 1
  fi
  flutter build ipa --release --build-name "$VERSION" --build-number "$BUILD_NUMBER" --export-options-plist "$EXPORT_OPTIONS_PLIST"
  cp build/ios/ipa/*.ipa "$SIGNED_IPA"
  echo "Signed iOS IPA generated: $SIGNED_IPA"
else
  flutter build ios --release --no-codesign --build-name "$VERSION" --build-number "$BUILD_NUMBER"
  rm -rf Payload
  mkdir -p Payload
  cp -R build/ios/iphoneos/Runner.app Payload/
  ditto -c -k --sequesterRsrc --keepParent Payload "$UNSIGNED_IPA"
  rm -rf Payload
  echo "Unsigned iOS IPA generated: $UNSIGNED_IPA"
  echo "This IPA must be signed with an Apple Developer certificate before device installation."
fi

popd >/dev/null
