#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${WING_VERSION:-1.0.7.3}"
TAGS="with_quic,with_utls,with_gvisor"
BUILD_NUMBER="${FLUTTER_BUILD_NUMBER:-10073}"
FLUTTER_BUILD_NAME="${FLUTTER_BUILD_NAME:-$VERSION}"
if [[ "$FLUTTER_BUILD_NAME" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)\.[0-9]+(\.[0-9]+)?$ ]]; then
  FLUTTER_BUILD_NAME="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.${BASH_REMATCH[3]}"
fi
DIST="$ROOT/dist"
APK="$DIST/wing-${VERSION}-android-universal.apk"

if ! command -v flutter >/dev/null 2>&1; then
  echo "Flutter is required to build Android APKs." >&2
  exit 1
fi

mkdir -p "$DIST"

pushd "$ROOT" >/dev/null
echo "Compiling Android Go backend (libwing_backend.so)..."

# All ABIs—including arm64-v8a—must be built with CGO_ENABLED=1 so Go uses
# Bionic getaddrinfo / Android netd DNS instead of failing on missing /etc/resolv.conf.
NDK_DIR="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-${ANDROID_NDK_LATEST_HOME:-}}}"
if [ -z "$NDK_DIR" ] || [ ! -d "$NDK_DIR" ]; then
  SDK_DIR="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-/usr/local/lib/android/sdk}}"
  if [ -d "$SDK_DIR/ndk" ]; then
    NDK_DIR="$(find "$SDK_DIR/ndk" -maxdepth 1 -mindepth 1 2>/dev/null | sort -V | tail -n 1 || true)"
  fi
fi
if [ -z "$NDK_DIR" ] || [ ! -d "$NDK_DIR" ]; then
  echo "Android NDK is required for Android backends." >&2
  exit 1
fi
LLVM_BIN="$(find "$NDK_DIR/toolchains/llvm/prebuilt" -mindepth 2 -maxdepth 2 -type d -name "bin" 2>/dev/null | head -n 1 || true)"
if [ -z "$LLVM_BIN" ] || [ ! -d "$LLVM_BIN" ]; then
  echo "Android NDK LLVM toolchain was not found." >&2
  exit 1
fi

find_ndk_clang() {
  local prefix="$1"
  local preferred="$LLVM_BIN/${prefix}21-clang"
  if [ -x "$preferred" ]; then
    printf '%s\n' "$preferred"
    return 0
  fi

  local candidates
  candidates="$(find "$LLVM_BIN" -maxdepth 1 -name "${prefix}[0-9]*-clang" ! -name '*clang++*' 2>/dev/null | sort -V || true)"
  if [ -z "$candidates" ]; then
    return 1
  fi

  local match
  match="$(printf '%s\n' "$candidates" | awk -v prefix="$prefix" '
    {
      name = $0
      sub(/^.*\//, "", name)
      sub("^" prefix, "", name)
      sub(/-clang$/, "", name)
      if (name + 0 >= 21) {
        print $0
        exit
      }
    }
  ')"
  if [ -n "$match" ]; then
    printf '%s\n' "$match"
    return 0
  fi

  printf '%s\n' "$candidates" | head -n 1
}

CLANG_ARM64="$(find_ndk_clang "aarch64-linux-android" || true)"
if [ -z "$CLANG_ARM64" ]; then
  echo "Android NDK arm64-v8a compiler was not found." >&2
  exit 1
fi
echo "Building arm64-v8a backend with NDK: $CLANG_ARM64..."
mkdir -p flutter_ui/android/app/src/main/jniLibs/arm64-v8a
env CGO_ENABLED=1 CC="$CLANG_ARM64" GOOS=android GOARCH=arm64 go build -tags "$TAGS" -o flutter_ui/android/app/src/main/jniLibs/arm64-v8a/libwing_backend.so ./mobile

CLANG_X86="$(find_ndk_clang "x86_64-linux-android" || true)"
if [ -z "$CLANG_X86" ]; then
  echo "Android NDK x86_64 compiler was not found." >&2
  exit 1
fi
echo "Building x86_64 backend with NDK: $CLANG_X86..."
mkdir -p flutter_ui/android/app/src/main/jniLibs/x86_64
env CGO_ENABLED=1 CC="$CLANG_X86" GOOS=android GOARCH=amd64 go build -tags "$TAGS" -o flutter_ui/android/app/src/main/jniLibs/x86_64/libwing_backend.so ./mobile

CLANG_ARM="$(find_ndk_clang "armv7a-linux-androideabi" || true)"
if [ -z "$CLANG_ARM" ]; then
  echo "Android NDK armeabi-v7a compiler was not found." >&2
  exit 1
fi
echo "Building armeabi-v7a backend with NDK: $CLANG_ARM..."
mkdir -p flutter_ui/android/app/src/main/jniLibs/armeabi-v7a
env CGO_ENABLED=1 CC="$CLANG_ARM" GOOS=android GOARCH=arm GOARM=7 go build -tags "$TAGS" -o flutter_ui/android/app/src/main/jniLibs/armeabi-v7a/libwing_backend.so ./mobile

popd >/dev/null

pushd "$ROOT/flutter_ui" >/dev/null
flutter pub get
flutter build apk --release --build-name "$FLUTTER_BUILD_NAME" --build-number "$BUILD_NUMBER"
popd >/dev/null

cp "$ROOT/flutter_ui/build/app/outputs/flutter-apk/app-release.apk" "$APK"
echo "Android APK generated: $APK"
