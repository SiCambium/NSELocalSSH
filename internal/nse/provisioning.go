package nse

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// First-run readiness.
//
// "Easy Config" is a sequence of questions, and the only part of it that
// belongs on the server is knowing which questions still need asking.
// This reads the device and reports what a new unit is still missing
// before it should be left in a customer's rack, so the wizard is driven
// by the device's actual state rather than by a fixed script that asks
// about things already done.
//
// Every check answers from `show config` and the device's own store. None
// of it consults a cloud account, so it works on a unit that has never
// been onboarded — which is the entire point after the cloud is gone.

// ProvisionStep is one thing to settle, and where to settle it.
type ProvisionStep struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Done    bool   `json:"done"`
	Detail  string `json:"detail"`
	Section string `json:"section,omitempty"` // Configuration section that fixes it
	Blocker bool   `json:"blocker"`           // must not be left undone
}

func (s *Server) handleProvisioning(w http.ResponseWriter, _ *http.Request) {
	cfgRaw, ok := s.cli(w, "show config", 25*time.Second)
	if !ok {
		return
	}
	cloud, err := FetchCloudConfig(s.Client, 20*time.Second)
	if err != nil {
		writeDeviceError(w, err)
		return
	}
	tree := ParseBlockTree(cfgRaw)
	leaf := func(prefix string) (string, bool) {
		for _, child := range tree.Children {
			if child.Block == nil && strings.HasPrefix(child.Line, prefix) {
				return strings.TrimPrefix(child.Line, prefix), true
			}
		}
		return "", false
	}

	steps := []ProvisionStep{}

	// The password cannot be inspected: the device stores it obfuscated
	// and there is no way to ask "is this still the factory one" without
	// trying it. So this is never reported as done — it is reported as
	// something only the operator can confirm, which is honest and is
	// also the right prompt for a unit out of its box.
	steps = append(steps, ProvisionStep{
		ID: "admin-password", Label: "Change the administrator password",
		Done: false, Blocker: true, Section: "password",
		Detail: "The device stores this obfuscated, so no check here can tell a factory password from a chosen one. Change it on a new unit and tick this yourself.",
	})

	host, hasHost := leaf("hostname ")
	steps = append(steps, ProvisionStep{
		ID: "hostname", Label: "Name the device", Done: hasHost && host != "",
		Section: "management", Detail: detailOr(host, "No hostname set; every alarm and backup from this unit will be hard to place."),
	})

	tz, hasTZ := leaf("timezone ")
	steps = append(steps, ProvisionStep{
		ID: "timezone", Label: "Set the timezone", Done: hasTZ && tz != "",
		Section: "management", Detail: detailOr(tz, "Without this, every event timestamp is in the wrong zone."),
	})

	ntp := 0
	for _, child := range tree.Children {
		if child.Block == nil && strings.HasPrefix(child.Line, "ntp server ") {
			ntp++
		}
	}
	steps = append(steps, ProvisionStep{
		ID: "ntp", Label: "Point at a time server", Done: ntp > 0, Section: "management",
		Detail: plural(ntp, "NTP server configured", "NTP servers configured"),
	})

	wanUp := 0
	for _, wan := range cloud.WANInterfaces {
		if wan.LANIntf != "" {
			wanUp++
		}
	}
	steps = append(steps, ProvisionStep{
		ID: "wan", Label: "Configure the internet link", Done: wanUp > 0, Blocker: true,
		Section: "wan", Detail: plural(wanUp, "WAN port configured", "WAN ports configured"),
	})

	pools := 0
	for _, v := range cloud.LANInterfaces {
		if v.DHCPPoolConfig.Enable {
			pools++
		}
	}
	steps = append(steps, ProvisionStep{
		ID: "lan", Label: "Hand out addresses on the LAN", Done: pools > 0,
		Section: "network", Detail: plural(pools, "VLAN serving DHCP", "VLANs serving DHCP"),
	})

	steps = append(steps, ProvisionStep{
		ID: "dns", Label: "Set name servers", Done: len(cloud.NameServer) > 0,
		Section: "dns", Detail: plural(len(cloud.NameServer), "name server set", "name servers set"),
	})

	steps = append(steps, ProvisionStep{
		ID: "logging", Label: "Send logs somewhere that outlives the device",
		Done: len(cloud.SyslogServer) > 0, Section: "management",
		Detail: "This device keeps a short, bounded event list and no long history of its own. A syslog target is how anything survives a reboot.",
	})

	steps = append(steps, ProvisionStep{
		ID: "backup", Label: "Take a backup", Done: false, Blocker: true,
		Detail: "Download the full backup once the unit is configured. It is the only copy that can rebuild this site, and nothing else holds the secrets it needs.",
	})

	blockers := 0
	remaining := 0
	for _, st := range steps {
		if st.Done {
			continue
		}
		remaining++
		if st.Blocker {
			blockers++
		}
	}
	writeJSON(w, map[string]any{
		"steps":     steps,
		"remaining": remaining,
		"blockers":  blockers,
		"device":    cloud.SystemName,
	})
}

func detailOr(value, empty string) string {
	if strings.TrimSpace(value) == "" {
		return empty
	}
	return value
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

