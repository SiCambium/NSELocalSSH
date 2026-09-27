package vpndiag

import (
	"embed"
	"io/fs"
)

// Playbooks ship compiled in: the app is distributed as a single binary with no
// sidecar files, and a .app bundle's own directory is not writable.
//
// These files are byte-identical copies of jev-vpn-debug-onbox/playbooks/, which
// is the upstream reference shared with a Python implementation. Do not edit
// them here to describe one device's CLI — that belongs in the EvidenceSource.
// TestPlaybooksMatchUpstream guards the copies when the reference is present.
//
//go:embed playbooks/*.tree.json
var playbookFS embed.FS

// Playbooks is the embedded set, rooted so a doc id maps to "<id>.tree.json".
func Playbooks() fs.FS {
	sub, err := fs.Sub(playbookFS, "playbooks")
	if err != nil {
		return playbookFS
	}
	return sub
}

// Doc ids of the shipped playbooks.
const (
	DocS2S       = "s2s-vpn-troubleshooting"
	DocWireGuard = "wireguard-vpn-troubleshooting"
)
