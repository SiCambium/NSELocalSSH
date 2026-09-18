package nse

// BuildVersion identifies this app's build. Named to stay clear of
// Version, which is already the device's own firmware information parsed
// from `show version` — the two would be confused constantly. It is overwritten at link time by the
// build scripts and CI:
//
//	go build -ldflags "-X nse-cli/internal/nse.BuildVersion=v0.3.0" ./cmd/nse-status
//
// A build without that flag reports "dev", which is the honest answer for
// one made straight from a working tree. Both binaries accept --version
// and print this, so a downloaded executable can always be identified —
// the release filename carries a version but nothing inside the file did,
// which made a bug report impossible to pin to a build.
var BuildVersion = "dev"
