#!/bin/sh
# Builds cmd/nse-app (the native desktop wrapper around webview_go) as a
# universal (arm64+amd64) macOS .app bundle, zipped into build/. macOS
# only — needs Xcode's clang/lipo/sips/iconutil, and the app itself needs
# CGO to link against Cocoa/WebKit.
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

version="${1:-dev}"
out="$root/build"
work="$out/.macos-work"
app_name="NSE Status"
app="$work/$app_name.app"
macos_dir="$app/Contents/MacOS"
resources="$app/Contents/Resources"

mkdir -p "$out"
rm -rf "$work"
mkdir -p "$macos_dir" "$resources"

export CGO_ENABLED=1
echo "  building arm64 slice"
GOOS=darwin GOARCH=arm64 go build -trimpath \
	-ldflags "-s -w -X nse-cli/internal/nse.BuildVersion=$version" \
	-o "$out/.nse-app-arm64" ./cmd/nse-app
echo "  building amd64 slice"
GOOS=darwin GOARCH=amd64 go build -trimpath \
	-ldflags "-s -w -X nse-cli/internal/nse.BuildVersion=$version" \
	-o "$out/.nse-app-amd64" ./cmd/nse-app
lipo -create -output "$macos_dir/nse-app" "$out/.nse-app-arm64" "$out/.nse-app-amd64"
rm -f "$out/.nse-app-arm64" "$out/.nse-app-amd64"

# Info.plist carries a hardcoded CFBundleShortVersionString that drifts
# from reality the moment a release is cut. Substitute the real version
# when it looks like one; a "dev" build keeps whatever the file says,
# since Finder rejects a non-numeric version string.
cp "$root/macos/Info.plist" "$app/Contents/Info.plist"
plist_version="$(printf %s "$version" | sed 's/^v//')"
case "$plist_version" in
	[0-9]*)
		/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $plist_version" \
			"$app/Contents/Info.plist" >/dev/null 2>&1 || true
		/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $plist_version" \
			"$app/Contents/Info.plist" >/dev/null 2>&1 || true
		;;
esac

if [ -f "$root/macos/icon.png" ]; then
	iconset="$out/.AppIcon.iconset"
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

# Ad-hoc sign so Gatekeeper's "unidentified developer" prompt is the only
# friction (no Apple Developer certificate is used here — this is not a
# notarized build).
codesign --force --deep --sign - "$app" 2>/dev/null || true

(cd "$work" && zip -qr "$out/NSE-Status-macOS-universal.zip" "$app_name.app")
rm -rf "$work"

echo "Done. $out/NSE-Status-macOS-universal.zip"
