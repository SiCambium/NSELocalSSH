package nse

import "strings"

// FeatureLicense mirrors the flags returned by `show feature-license`.
// These 7 flags gate NSE Security Plus features on this device — confirmed
// by diffing a paid vs. free cnMaestro account: HighAvailability -> Basic
// tab HA; GeoIPFirewall -> Firewall GEO IP filters (both directions);
// DNSFilter -> DNS tab content-filtering mode; Tailscale -> VPN tab
// Tailscale section; DeviceFingerprint -> per-VLAN "Device Identification";
// PortScan -> per-VLAN "Vulnerability Scan"; OverlayWAN -> WAN tab's
// "Add Virtual WAN".
type FeatureLicense struct {
	DeviceFingerprint bool `json:"device_fingerprint"`
	PortScan          bool `json:"port_scan"`
	DNSFilter         bool `json:"dns_filter"`
	HighAvailability  bool `json:"high_availability"`
	GeoIPFirewall     bool `json:"geoip_firewall"`
	Tailscale         bool `json:"tailscale"`
	OverlayWAN        bool `json:"overlay_wan"`
}

// ParseFeatureLicense parses `show feature-license` output, e.g.:
//
//	device-fingerprint : Enabled
//	port-scan : Enabled
//	dns-filter : Enabled
//	high-availability : Enabled
//	geoip-firewall : Enabled
//	tailscale : Enabled
//	overlay-wan : Enabled
func ParseFeatureLicense(raw string) FeatureLicense {
	var fl FeatureLicense
	for _, line := range linesOf(raw, "show feature-license") {
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		enabled := strings.EqualFold(strings.TrimSpace(val), "Enabled")
		switch strings.TrimSpace(key) {
		case "device-fingerprint":
			fl.DeviceFingerprint = enabled
		case "port-scan":
			fl.PortScan = enabled
		case "dns-filter":
			fl.DNSFilter = enabled
		case "high-availability":
			fl.HighAvailability = enabled
		case "geoip-firewall":
			fl.GeoIPFirewall = enabled
		case "tailscale":
			fl.Tailscale = enabled
		case "overlay-wan":
			fl.OverlayWAN = enabled
		}
	}
	return fl
}
