#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="${IOS_PROVISIONING_PROFILE:-}"
TUNNEL_PROFILE="${IOS_PACKET_TUNNEL_PROVISIONING_PROFILE:-}"
P12="${IOS_P12_PATH:-}"
P12_PASSWORD="${IOS_P12_PASSWORD:-}"
TEAM_ID="${IOS_TEAM_ID:-}"
BUNDLE_ID="${IOS_BUNDLE_ID:-com.highmae.wing}"
VERSION="${WING_VERSION:-1.0.6.2}"
BUILD_NUMBER="${FLUTTER_BUILD_NUMBER:-10062}"

for value in PROFILE TUNNEL_PROFILE P12 TEAM_ID; do
  if [[ -z "${!value}" ]]; then
    echo "$value is required" >&2
    exit 1
  fi
done
if [[ ! -f "$PROFILE" || ! -f "$TUNNEL_PROFILE" || ! -f "$P12" ]]; then
  echo "A provisioning profile or P12 file does not exist." >&2
  exit 1
fi

KEYCHAIN="$RUNNER_TEMP/wing-signing.keychain-db"
KEYCHAIN_PASSWORD="$(openssl rand -hex 24)"
PROFILE_UUID="$(security cms -D -i "$PROFILE" | plutil -extract UUID raw -)"
PROFILE_NAME="$(security cms -D -i "$PROFILE" | plutil -extract Name raw -)"
TUNNEL_PROFILE_UUID="$(security cms -D -i "$TUNNEL_PROFILE" | plutil -extract UUID raw -)"
TUNNEL_PROFILE_NAME="$(security cms -D -i "$TUNNEL_PROFILE" | plutil -extract Name raw -)"
mkdir -p "$HOME/Library/MobileDevice/Provisioning Profiles"
cp "$PROFILE" "$HOME/Library/MobileDevice/Provisioning Profiles/$PROFILE_UUID.mobileprovision"
cp "$TUNNEL_PROFILE" "$HOME/Library/MobileDevice/Provisioning Profiles/$TUNNEL_PROFILE_UUID.mobileprovision"

security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN"
security set-keychain-settings -lut 21600 "$KEYCHAIN"
security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN"
security import "$P12" -P "$P12_PASSWORD" -A -t cert -f pkcs12 -k "$KEYCHAIN"
security list-keychain -d user -s "$KEYCHAIN" login.keychain-db
security set-key-partition-list -S apple-tool:,apple: -s -k "$KEYCHAIN_PASSWORD" "$KEYCHAIN"

EXPORT_PLIST="$RUNNER_TEMP/wing-export-options.plist"
cat >"$EXPORT_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>method</key><string>development</string>
<key>signingStyle</key><string>manual</string>
<key>teamID</key><string>$TEAM_ID</string>
<key>provisioningProfiles</key><dict>
<key>$BUNDLE_ID</key><string>$PROFILE_NAME</string>
<key>$BUNDLE_ID.PacketTunnel</key><string>$TUNNEL_PROFILE_NAME</string>
</dict>
</dict></plist>
EOF

export IOS_EXPORT_OPTIONS_PLIST="$EXPORT_PLIST"
export FLUTTER_BUILD_NAME="${VERSION%.*}"
export FLUTTER_BUILD_NUMBER="$BUILD_NUMBER"
bash "$ROOT/scripts/package-ios.sh"
