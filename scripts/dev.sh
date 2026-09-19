#!/bin/sh
# Runs cmd/nse-status with live reload for the edit-save-look loop.
#
# The UI normally ships inside the binary via //go:embed, so a CSS or JS
# edit is invisible until the process is rebuilt and restarted. Setting
# NSE_DEV_STATIC serves web/static from disk instead and turns on the
# reload channel the page subscribes to, so a saved edit shows up on the
# next repaint.
#
# Go changes still need a restart: the page can reload itself, but the
# process cannot swap itself out. After a `git pull` that touched any Go
# file, stop this and start it again — `go run` recompiles each time, so
# a restart picks up everything.
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

# Both are overridable, so a second instance can run against another
# device without editing this file:
#   NSE_LISTEN=127.0.0.1:8099 sh scripts/dev.sh
NSE_DEV_STATIC="${NSE_DEV_STATIC:-$root/web/static}"
NSE_LISTEN="${NSE_LISTEN:-127.0.0.1:8080}"
export NSE_DEV_STATIC NSE_LISTEN

echo "dev server on http://$NSE_LISTEN — serving $NSE_DEV_STATIC from disk, live reload on"
exec go run ./cmd/nse-status
