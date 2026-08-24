#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${WING_VERSION:-1.0.6}"
BUILD_NUMBER="${FLUTTER_BUILD_NUMBER:-10060}"
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

# 1. Always compile arm64-v8a (supports pure Go / CGO_ENABLED=0)
echo "Building arm64-v8a backend..."
mkdir -p flutter_ui/android/app/src/main/jniLibs/arm64-v8a
env CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build -o flutter_ui/android/app/src/main/jniLibs/arm64-v8a/libwing_backend.so ./mobile

# 2. Check for Android NDK to compile other architectures
NDK_DIR="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-${ANDROID_NDK_LATEST_HOME:-}}}"
if [ -z "$NDK_DIR" ] || [ ! -d "$NDK_DIR" ]; then
  if [ -d "${ANDROID_HOME:-${ANDROID_SDK_ROOT:-/usr/local/lib/android/sdk}}/ndk" ]; then
    NDK_DIR="$(find "${ANDROID_HOME:-${ANDROID_SDK_ROOT:-/usr/local/lib/android/sdk}}/ndk" -maxdepth 1 -mindepth 1 2>/dev/null | sort -V | tail -n 1 || true)"
  fi
fi

if [ -n "$NDK_DIR" ] && [ -d "$NDK_DIR" ]; then
  echo "Found Android NDK at: $NDK_DIR"
  LLVM_BIN="$(find "$NDK_DIR/toolchains/llvm/prebuilt" -type d -name "bin" 2>/dev/null | head -n 1 || true)"
  if [ -n "$LLVM_BIN" ] && [ -d "$LLVM_BIN" ]; then
    # x86_64 (for emulators like LDPlayer / Thunder)
    CLANG_X86="$(find "$LLVM_BIN" -name "x86_64-linux-android*-clang" 2>/dev/null | grep -v 'clang++' | head -n 1 || true)"
    if [ -n "$CLANG_X86" ]; then
      echo "Building x86_64 backend with NDK: $CLANG_X86..."
      mkdir -p flutter_ui/android/app/src/main/jniLibs/x86_64
      env CGO_ENABLED=1 CC="$CLANG_X86" GOOS=android GOARCH=amd64 go build -o flutter_ui/android/app/src/main/jniLibs/x86_64/libwing_backend.so ./mobile || true
    fi

    # armeabi-v7a (32-bit ARM)
    CLANG_ARM="$(find "$LLVM_BIN" -name "armv7a-linux-androideabi*-clang" 2>/dev/null | grep -v 'clang++' | head -n 1 || true)"
    if [ -n "$CLANG_ARM" ]; then
      echo "Building armeabi-v7a backend with NDK: $CLANG_ARM..."
      mkdir -p flutter_ui/android/app/src/main/jniLibs/armeabi-v7a
      env CGO_ENABLED=1 CC="$CLANG_ARM" GOOS=android GOARCH=arm GOARM=7 go build -o flutter_ui/android/app/src/main/jniLibs/armeabi-v7a/libwing_backend.so ./mobile || true
    fi
  fi
fi

popd >/dev/null

pushd "$ROOT/flutter_ui" >/dev/null
flutter pub get
flutter build apk --release --build-name "$FLUTTER_BUILD_NAME" --build-number "$BUILD_NUMBER"
popd >/dev/null

cp "$ROOT/flutter_ui/build/app/outputs/flutter-apk/app-release.apk" "$APK"
echo "Android APK generated: $APK"
