package nse

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNextAvailablePoolNumber(t *testing.T) {
	if got := nextAvailablePoolNumber(nil); got != 1 {
		t.Fatalf("nextAvailablePoolNumber(nil) = %d, want 1", got)
	}
	pools := []DHCPPoolSettings{{Pool: 1}, {Pool: 3}, {Pool: 2}}
	if got := nextAvailablePoolNumber(pools); got != 4 {
		t.Fatalf("nextAvailablePoolNumber(%v) = %d, want 4", pools, got)
	}
}

func TestPoolNumberForVLANMatchesByStartAddress(t *testing.T) {
	cloud := CloudConfig{
		LANInterfaces: []LANInterface{
			{VLANID: 1, DHCPPoolConfig: DHCPPoolConfig{StartAddress: "172.21.1.30"}},
			{VLANID: 30, DHCPPoolConfig: DHCPPoolConfig{StartAddress: "192.168.21.30"}},
		},
	}
	pools := []DHCPPoolSettings{
		{Pool: 1, AddressRange: "172.21.1.30 172.21.1.250"},
		{Pool: 2, AddressRange: "192.168.21.30 192.168.21.250"},
	}
	if got := poolNumberForVLAN(1, cloud, pools); got != 1 {
		t.Fatalf("poolNumberForVLAN(1) = %d, want 1", got)
	}
	// Confirms pool numbers don't have to match VLAN IDs.
	if got := poolNumberForVLAN(30, cloud, pools); got != 2 {
		t.Fatalf("poolNumberForVLAN(30) = %d, want 2 (pool numbers are independent of VLAN ID)", got)
	}
	if got := poolNumberForVLAN(999, cloud, pools); got != 0 {
		t.Fatalf("poolNumberForVLAN(999) = %d, want 0 (no match)", got)
	}
}

func TestConfigNetworkVLANCreateRequiresIPAndMask(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/network", strings.NewReader(`{"action":"vlan_create","vlan_id":50}`))
	rec := httptest.NewRecorder()
	s.handleConfigNetwork(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigNetworkDHCPScopeRequiresFields(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/network", strings.NewReader(`{"action":"dhcp_scope","vlan_id":1,"dhcp":{"start_ip":"172.21.1.30"}}`))
	rec := httptest.NewRecorder()
	s.handleConfigNetwork(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigNetworkPortSwitchportRequiresPort(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/network", strings.NewReader(`{"action":"port_switchport","mode":"access","access_vlan":"30"}`))
	rec := httptest.NewRecorder()
	s.handleConfigNetwork(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigNetworkPortSwitchportRejectsUnknownMode(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/network", strings.NewReader(`{"action":"port_switchport","port":3,"mode":"turbo"}`))
	rec := httptest.NewRecorder()
	s.handleConfigNetwork(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigNetworkPortSwitchportAccessRequiresVLAN(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/network", strings.NewReader(`{"action":"port_switchport","port":3,"mode":"access"}`))
	rec := httptest.NewRecorder()
	s.handleConfigNetwork(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigNetworkPortSwitchportTrunkRequiresVLANs(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/network", strings.NewReader(`{"action":"port_switchport","port":5,"mode":"trunk","native_vlan":"1"}`))
	rec := httptest.NewRecorder()
	s.handleConfigNetwork(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigNetworkPortSpeedRequiresPort(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/network", strings.NewReader(`{"action":"port_speed","speed":"auto"}`))
	rec := httptest.NewRecorder()
	s.handleConfigNetwork(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigNetworkPortSpeedRequiresAtLeastOneField(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/network", strings.NewReader(`{"action":"port_speed","port":3}`))
	rec := httptest.NewRecorder()
	s.handleConfigNetwork(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigNetworkPortSpeedRejectsInvalidSpeed(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/network", strings.NewReader(`{"action":"port_speed","port":3,"speed":"1000"}`))
	rec := httptest.NewRecorder()
	s.handleConfigNetwork(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s (speed must not accept 1000 -- that's only valid for advertise)", rec.Code, rec.Body.String())
	}
}

func TestConfigNetworkPortSpeedRejectsInvalidDuplex(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/network", strings.NewReader(`{"action":"port_speed","port":3,"duplex":"auto"}`))
	rec := httptest.NewRecorder()
	s.handleConfigNetwork(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s (duplex has no auto value)", rec.Code, rec.Body.String())
	}
}

func TestConfigNetworkPortSpeedAcceptsValidAdvertise(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/network", strings.NewReader(`{"action":"port_speed","port":3,"advertise":"1000"}`))
	rec := httptest.NewRecorder()
	s.handleConfigNetwork(rec, req)
	if rec.Code == http.StatusBadRequest {
		t.Fatalf("advertise=1000 rejected as invalid input: %s", rec.Body.String())
	}
}

func TestConfigNetworkPortShutdownRequiresEnabled(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/network", strings.NewReader(`{"action":"port_shutdown","port":3}`))
	rec := httptest.NewRecorder()
	s.handleConfigNetwork(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigWANEnableRequiresName(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/wan", strings.NewReader(`{"action":"enable","port":3}`))
	rec := httptest.NewRecorder()
	s.handleConfigWAN(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigWANLoadBalanceModeRejectsInvalid(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/wan", strings.NewReader(`{"action":"load_balance_mode","port":1,"lb_mode":"turbo"}`))
	rec := httptest.NewRecorder()
	s.handleConfigWAN(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigWANChangePortRequiresNewPort(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/wan", strings.NewReader(`{"action":"change_port","port":1,"name":"wan1"}`))
	rec := httptest.NewRecorder()
	s.handleConfigWAN(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigWANChangePortRejectsSamePort(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/wan", strings.NewReader(`{"action":"change_port","port":1,"new_port":1,"name":"wan1"}`))
	rec := httptest.NewRecorder()
	s.handleConfigWAN(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigWANChangePortRequiresName(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/wan", strings.NewReader(`{"action":"change_port","port":1,"new_port":3}`))
	rec := httptest.NewRecorder()
	s.handleConfigWAN(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigWANLoadBalanceModeAcceptsValid(t *testing.T) {
	s := testConfigServer(t)
	for _, mode := range []string{"shared", "backup", "disabled"} {
		req := httptest.NewRequest(http.MethodPost, "/api/config/wan", strings.NewReader(`{"action":"load_balance_mode","port":1,"lb_mode":"`+mode+`"}`))
		rec := httptest.NewRecorder()
		s.handleConfigWAN(rec, req)
		// SkipConnect means the actual SSH apply will fail with a 502 further
		// down the handler; what this test guards is that the mode itself
		// clears validation instead of being rejected as invalid input.
		if rec.Code == http.StatusBadRequest {
			t.Fatalf("mode %q was rejected as invalid input: %s", mode, rec.Body.String())
		}
	}
}
