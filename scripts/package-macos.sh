#!/bin/sh
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

app_name="NSE Status"
dist="$root/dist"
app="$dist/$app_name.app"
macos="$app/Contents/MacOS"
resources="$app/Contents/Resources"

export PATH="/usr/local/go/bin:/opt/homebrew/bin:/usr/bin:/bin"
export CGO_ENABLED=1

rm -rf "$app"
mkdir -p "$macos" "$resources"

go build -o "$macos/nse-app" ./cmd/nse-app
cp "$root/macos/Info.plist" "$app/Contents/Info.plist"

if [ -f "$root/macos/icon.png" ]; then
  iconset="$dist/AppIcon.iconset"
  rm -rf "$iconset"
  mkdir -p "$iconset"
  sips -z 16 16     "$root/macos/icon.png" --out "$iconset/icon_16x16.png" >/dev/null
  sips -z 32 32     "$root/macos/icon.png" --out "$iconset/icon_16x16@2x.png" >/dev/null
  sips -z 32 32     "$root/macos/icon.png" --out "$iconset/icon_32x32.png" >/dev/null
  sips -z 64 64     "$root/macos/icon.png" --out "$iconset/icon_32x32@2x.png" >/dev/null
  sips -z 128 128   "$root/macos/icon.png" --out "$iconset/icon_128x128.png" >/dev/null
  sips -z 256 256   "$root/macos/icon.png" --out "$iconset/icon_128x128@2x.png" >/dev/null
  sips -z 256 256   "$root/macos/icon.png" --out "$iconset/icon_256x256.png" >/dev/null
  sips -z 512 512   "$root/macos/icon.png" --out "$iconset/icon_256x256@2x.png" >/dev/null
  sips -z 512 512   "$root/macos/icon.png" --out "$iconset/icon_512x512.png" >/dev/null
  sips -z 1024 1024 "$root/macos/icon.png" --out "$iconset/icon_512x512@2x.png" >/dev/null
  iconutil -c icns "$iconset" -o "$resources/AppIcon.icns"
  rm -rf "$iconset"
fi

if [ -f "$root/.env" ]; then
  cp "$root/.env" "$resources/.env"
fi

echo "Built $app"
echo "Open with: open \"$app\""
