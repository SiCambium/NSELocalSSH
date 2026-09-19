package nse

import (
	"encoding/json"
	"strings"
)

// The device's own configuration store.
//
// `service show config` prints the internal JSON the device configures
// itself from: 721 keys on a 2.3-r6 NSE3000, including every field that
// `show config` declines to print as a CLI line. Those fields were never
// the cloud's to know — cnMaestro reads this same store — so nothing here
// depends on a cloud account, a cloud connection, or a unit ever having
// been onboarded.
//
// That last point is why this exists. `service show cloud-json-config`
// carries the same values in a friendlier shape, but it is a snapshot
// regenerated *for* the cloud, and the code comment on it has always
// warned that a unit which is never cloud-managed may never populate it.
// A site commissioned after the cloud goes away is exactly that unit.
//
// **This command dumps every secret in cleartext.** The rule here is the
// same as cloudconfig.go's and is enforced by construction: this file
// declares the handful of display-safe fields it wants and unmarshals
// nothing else, so a secret cannot reach the UI by accident even if a
// future firmware adds one next to the fields below.
type serviceConfig struct {
	InterfaceEth map[string]serviceEth `json:"interface_eth"`
}

// serviceEth is the display-safe subset of one physical port's entry.
// Everything omitted here is either expressible in `show config` (and so
// read from there, which is the authority) or carries a credential.
type serviceEth struct {
	Type              string `json:"type"`
	WANName           string `json:"wan_name"`
	VLAN              string `json:"vlan"`
	PeriodicSpeedtest string `json:"periodic_speedtest"`
	DynDNSMode        string `json:"dyndns_mode"`
	SpareIPMode       string `json:"spare_ip_mode"`
	TrafficShaping    string `json:"traffic_shaping"`
}

// ParseServiceConfig reads `service show config`. The CLI echo and prompt
// surround the JSON, so the object is cut out by its braces rather than
// by stripCLI, which would leave the trailing prompt inside.
//
// A device that answers something other than JSON returns ok=false and no
// error: this is an enrichment source, and the caller already has the
// authoritative `show config` in hand.
func ParseServiceConfig(raw string) (serviceConfig, bool) {
	var out serviceConfig
	start := strings.Index(raw, "{")
	end := strings.LastIndex(raw, "}")
	if start < 0 || end <= start {
		return out, false
	}
	if err := json.Unmarshal([]byte(raw[start:end+1]), &out); err != nil {
		return out, false
	}
	return out, len(out.InterfaceEth) > 0
}

// enableDisable normalizes the store's own spelling into the booleans the
// rest of the app uses. Anything unrecognized is left alone rather than
// guessed at, so an unexpected value reads as "not set" and not as "off".
func enableDisable(v string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "enable", "enabled", "true", "yes":
		return true, true
	case "disable", "disabled", "false", "no":
		return false, true
	}
	return false, false
}

// enrichFromServiceConfig fills the WAN fields `show config` cannot
// express, from the device's own store.
//
// The same rule as enrichFromCloudJSON governs what may be listed here,
// and for the same reason: **only fields the CLI cannot write**. A field
// this app can edit must be read from `show config`, which is the running
// configuration; filling it from anywhere else risks showing a stale
// value as though a change had not applied.
//
// Currently: periodic speedtest, DynDNS mode, the WAN's VLAN tag, spare
// IP mode and traffic shaping. Every one of those is on the "no confirmed
// leaf" list in cloudconfig_fallback.go's doc comment.
func enrichFromServiceConfig(cfg *CloudConfig, svc serviceConfig) {
	for i := range cfg.WANInterfaces {
		w := &cfg.WANInterfaces[i]
		// The store is keyed by port number ("1"), the config by port
		// name ("eth1").
		src, ok := svc.InterfaceEth[strings.TrimPrefix(w.LANIntf, "eth")]
		if !ok {
			continue
		}
		if on, known := enableDisable(src.PeriodicSpeedtest); known {
			w.Speedtest = on
		}
		if w.Name == "" {
			w.Name = src.WANName
		}
		if w.VLAN == "" {
			w.VLAN = src.VLAN
		}
		if w.SpareIPMode == "" {
			w.SpareIPMode = src.SpareIPMode
		}
		if w.TrafficShaping == "" {
			w.TrafficShaping = src.TrafficShaping
		}
		if w.DynDNSConfig.Mode == "" {
			w.DynDNSConfig.Mode = src.DynDNSMode
		}
	}
}
