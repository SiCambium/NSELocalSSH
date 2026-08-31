package nse

import "testing"

func TestParseFeatureLicenseAllEnabled(t *testing.T) {
	raw := `show feature-license
-----------------------------------------------
device-fingerprint : Enabled
port-scan : Enabled
dns-filter : Enabled
high-availability : Enabled
geoip-firewall : Enabled
tailscale : Enabled
overlay-wan : Enabled
-----------------------------------------------
NSE-Caravan(config)# `

	fl := ParseFeatureLicense(raw)
	want := FeatureLicense{
		DeviceFingerprint: true,
		PortScan:          true,
		DNSFilter:         true,
		HighAvailability:  true,
		GeoIPFirewall:     true,
		Tailscale:         true,
		OverlayWAN:        true,
	}
	if fl != want {
		t.Fatalf("ParseFeatureLicense() = %+v, want %+v", fl, want)
	}
}

func TestParseFeatureLicenseSomeDisabled(t *testing.T) {
	raw := `show feature-license
-----------------------------------------------
device-fingerprint : Disabled
port-scan : Disabled
dns-filter : Disabled
high-availability : Disabled
geoip-firewall : Disabled
tailscale : Disabled
overlay-wan : Disabled
-----------------------------------------------
NSE-Caravan(config)# `

	fl := ParseFeatureLicense(raw)
	if fl != (FeatureLicense{}) {
		t.Fatalf("ParseFeatureLicense() = %+v, want all false", fl)
	}
}
