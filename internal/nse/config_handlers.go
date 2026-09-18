package nse

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// handleLicense reports which Security Plus features are enabled on this
// device, so the frontend can grey out and label the gated controls the
// same way cnMaestro does rather than hiding them outright.
func (s *Server) handleLicense(w http.ResponseWriter, _ *http.Request) {
	raw, ok := s.cli(w, "show feature-license", 20*time.Second)
	if !ok {
		return
	}
	writeJSON(w, map[string]any{"license": ParseFeatureLicense(raw)})
}

// containsCLILineBreak reports whether a free-text value would break out
// of the CLI line it is interpolated into.
//
// The guarantee lives lower down, in Client.validateCLILine, which every
// command passes through: a line break can no longer reach the device
// from any path, present or future, without a handler having to remember
// to check. This is only for handlers that want to reject the value up
// front with a specific 400 rather than let it fail as an apply error.
func containsCLILineBreak(s string) bool {
	return strings.ContainsAny(s, "\r\n")
}

// writeDeviceError answers a request that failed while talking to the
// device, whether reading or applying. Most such failures are the
// device's — unreachable, or it rejected the command — which is a 502.
// A command refused for spanning lines is the caller's, and answering
// "bad gateway" when nothing was wrong with the gateway sends whoever is
// debugging it in the wrong direction.
func writeDeviceError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrCLILineBreak) {
		writeSettingsError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeSettingsError(w, http.StatusBadGateway, err.Error())
}

// redactOutcome strips secret values out of the CLI lines an ApplyOutcome
// echoes back. SafeApplier returns the exact lines it sent so the UI can
// show what was applied, but for a write-only secret — a Tailscale auth
// key, an IPS oinkcode, a RADIUS shared secret — that line contains the
// secret itself, and returning it unaltered would put it back on the wire
// and into whatever the frontend renders or a caller logs. Handlers that
// can carry a secret pass their outcome through this first.
func redactOutcome(o ApplyOutcome) ApplyOutcome {
	for i, l := range o.Lines {
		if secretLine(l.Line) {
			o.Lines[i].Line = redactSecretLine(l.Line)
		}
		o.Lines[i].Output = SanitizeCLIOutput(l.Output)
	}
	return o
}

type confirmRequest struct {
	Token string `json:"token"`
}

// handleConfigConfirm commits a provisional risky change, cancelling its
// auto-rollback. See SafeApplier.
func (s *Server) handleConfigConfirm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isSameOrigin(r) {
		writeCrossOriginBlocked(w)
		return
	}
	var req confirmRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" {
		writeSettingsError(w, http.StatusBadRequest, "token is required")
		return
	}
	outcome, err := s.safeApplier().Confirm(req.Token)
	if err != nil {
		writeSettingsError(w, http.StatusGone, err.Error())
		return
	}
	writeJSON(w, outcome)
}

// handleConfigNetwork serves and edits VLANs (cloud-json-config's
// lan_interfaces) and physical LAN port switchport settings (from the
// existing show-config-derived ParseLANConfig, which already covers this
// well — no need to duplicate it against cloud-json-config's dynamic
// interface_ethN_* keys for Phase 1).
func (s *Server) handleConfigNetwork(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleGetConfigNetwork(w, r)
	case http.MethodPost:
		s.handlePostConfigNetwork(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleGetConfigNetwork(w http.ResponseWriter, _ *http.Request) {
	cloud, err := FetchCloudConfig(s.Client, 20*time.Second)
	if err != nil {
		writeDeviceError(w, err)
		return
	}
	cfgRaw, ok := s.cli(w, "show config", 25*time.Second)
	if !ok {
		return
	}
	// `show config` only carries speed/duplex/advertise when they have been
	// FORCED — an auto-negotiating port has no such lines at all, which is
	// why the ports table could only ever show "auto" and "-". The
	// negotiated values live in `show interface brief`.
	brief, ok := s.cli(w, "show interface brief", 20*time.Second)
	if !ok {
		return
	}
	lan := ParseLANConfig(cfgRaw)
	writeJSON(w, map[string]any{
		// config_source tells the frontend whether VLAN names are real
		// values or simply absent — see CloudConfigFromShowConfig for what
		// the fallback can't express.
		"config_source": cloud.Source,
		"vlans":         cloud.LANInterfaces,
		"ports":         lan.Ports,
		"bindings":      bindingsByVLAN(cloud, lan),
		"link":          linkByInterface(ParseInterfaceBrief(brief)),
	})
}

// linkByInterface keys operational link state by interface name, lowercased
// so it can be looked up from the configured port list regardless of how
// either side spells it.
func linkByInterface(rows []Interface) map[string]Interface {
	out := map[string]Interface{}
	for _, r := range rows {
		out[strings.ToLower(r.Interface)] = r
	}
	return out
}

// bindingsByVLAN regroups DHCP reservations under the VLAN they belong to.
// The CLI keys reservations by pool number, but both cnMaestro and this UI
// present them per-VLAN, and the pool a VLAN owns is only discoverable by
// matching its scope — poolNumberForVLAN does that matching.
//
// The keys are strings because this map is serialized to JSON, where
// object keys are strings regardless.
func bindingsByVLAN(cloud CloudConfig, lan LANConfig) map[string][]MACBinding {
	merged := MergeBindingDescriptions(lan.Bindings, cloud)
	byPool := map[int][]MACBinding{}
	for _, b := range merged {
		byPool[b.Pool] = append(byPool[b.Pool], b)
	}
	out := map[string][]MACBinding{}
	for _, v := range cloud.LANInterfaces {
		list := byPool[poolNumberForVLAN(v.VLANID, cloud, lan.DHCPPools)]
		if list == nil {
			list = []MACBinding{}
		}
		out[strconv.Itoa(v.VLANID)] = list
	}
	return out
}

type dhcpOptionRequest struct {
	Code int `json:"code"`
	// Type is the device's type token ("IP"/"text"). Optional: an empty
	// value is inferred from Value (see InferDHCPOptionType), so the UI
	// can keep accepting a plain "<code> <value>" line.
	Type  string `json:"type"`
	Value string `json:"value"`
}

type dhcpScopeRequest struct {
	StartIP      string              `json:"start_ip"`
	EndIP        string              `json:"end_ip"`
	Router       string              `json:"router"`
	DNS          string              `json:"dns"`
	DNSSecondary string              `json:"dns_secondary"`
	Domain       string              `json:"domain"`
	LeaseDays    int                 `json:"lease_days"`
	LeaseHours   int                 `json:"lease_hours"`
	LeaseMins    int                 `json:"lease_mins"`
	Options      []dhcpOptionRequest `json:"options"`
}

func (d dhcpScopeRequest) valid() bool {
	return d.StartIP != "" && d.EndIP != "" && d.Router != "" && d.DNS != ""
}

func (d dhcpScopeRequest) options() []DHCPOption {
	out := make([]DHCPOption, 0, len(d.Options))
	for _, o := range d.Options {
		if o.Code > 0 && o.Value != "" {
			out = append(out, DHCPOption{Code: o.Code, Type: o.Type, Value: o.Value})
		}
	}
	return out
}

type networkRequest struct {
	Action           string            `json:"action"`
	VLANID           int               `json:"vlan_id"`
	IP               string            `json:"ip"`
	Mask             string            `json:"mask"`
	ManagementAccess *bool             `json:"management_access"`
	InterVLANRouting *bool             `json:"inter_vlan_routing"`
	DHCP             *dhcpScopeRequest `json:"dhcp"`

	// LAN port switchport fields, used by "port_switchport"/"port_shutdown".
	Port         int    `json:"port"`
	Mode         string `json:"mode"` // "access" | "trunk"
	AccessVLAN   string `json:"access_vlan"`
	NativeVLAN   string `json:"native_vlan"`
	AllowedVLANs string `json:"allowed_vlans"`
	Enabled      *bool  `json:"enabled"`

	// MAC binding fields, used by "mac_bind_add"/"mac_bind_delete".
	MAC    string `json:"mac"`
	BindIP string `json:"bind_ip"`

	// LAN port PHY fields, used by "port_speed".
	Speed     string `json:"speed"`     // "10" | "100" | "auto"
	Duplex    string `json:"duplex"`    // "full" | "half"
	Advertise string `json:"advertise"` // "10" | "100" | "1000" | "auto"
}

// currentPortVLAN looks up a single eth port's existing switchport config
// out of a fresh `show config` capture, returning the zero value if the
// port has no config of its own yet.
func currentPortVLAN(cfgRaw string, port int) PortVLAN {
	name := fmt.Sprintf("eth%d", port)
	for _, p := range ParseLANConfig(cfgRaw).Ports {
		if p.Interface == name {
			return p
		}
	}
	return PortVLAN{}
}

// poolNumberForVLAN finds the existing "ip dhcp pool N" that belongs to a
// VLAN by matching its cloud-json-config start address against the
// address-range of each parsed pool — pool numbers are independent,
// incrementing bookkeeping (pool 1, 2, 3... in creation order) with no
// relationship to VLAN ID, confirmed by this device's own config (VLAN
// 30's pool is "ip dhcp pool 2", not "pool 30").
func poolNumberForVLAN(vlanID int, cloud CloudConfig, pools []DHCPPoolSettings) int {
	for _, v := range cloud.LANInterfaces {
		if v.VLANID != vlanID || v.DHCPPoolConfig.StartAddress == "" {
			continue
		}
		for _, p := range pools {
			if strings.HasPrefix(p.AddressRange, v.DHCPPoolConfig.StartAddress+" ") {
				return p.Pool
			}
		}
	}
	return 0
}

func nextAvailablePoolNumber(pools []DHCPPoolSettings) int {
	max := 0
	for _, p := range pools {
		if p.Pool > max {
			max = p.Pool
		}
	}
	return max + 1
}

func (s *Server) handlePostConfigNetwork(w http.ResponseWriter, r *http.Request) {
	if !isSameOrigin(r) {
		writeCrossOriginBlocked(w)
		return
	}
	var req networkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSettingsError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	isPortAction := req.Action == "port_switchport" || req.Action == "port_shutdown" || req.Action == "port_speed"
	if !isPortAction && req.VLANID < 1 {
		writeSettingsError(w, http.StatusBadRequest, "vlan_id is required")
		return
	}
	if isPortAction && req.Port < 1 {
		writeSettingsError(w, http.StatusBadRequest, "port is required")
		return
	}
	key := fmt.Sprintf("interface vlan %d", req.VLANID)

	var block ConfigBlock
	switch req.Action {
	case "port_switchport":
		switch req.Mode {
		case "access":
			if req.AccessVLAN == "" {
				writeSettingsError(w, http.StatusBadRequest, "access_vlan is required for access mode")
				return
			}
		case "trunk":
			if req.NativeVLAN == "" || req.AllowedVLANs == "" {
				writeSettingsError(w, http.StatusBadRequest, "native_vlan and allowed_vlans are required for trunk mode")
				return
			}
		default:
			writeSettingsError(w, http.StatusBadRequest, "mode must be 'access' or 'trunk'")
			return
		}
		cfgRaw, ok := s.cli(w, "show config", 25*time.Second)
		if !ok {
			return
		}
		current := currentPortVLAN(cfgRaw, req.Port)
		var leaves []string
		if req.Mode == "access" {
			leaves = LANPortAccessLines(current, req.AccessVLAN)
		} else {
			leaves = LANPortTrunkLines(current, req.NativeVLAN, req.AllowedVLANs)
		}
		block = ConfigBlock{
			Name:  "lan-port-switchport",
			Lines: BuildInterfaceEthLines(req.Port, leaves),
			Risk:  ClassifyRisk("lan-port"),
			Keys:  []string{fmt.Sprintf("interface eth %d", req.Port)},
		}
	case "port_shutdown":
		if req.Enabled == nil {
			writeSettingsError(w, http.StatusBadRequest, "enabled is required")
			return
		}
		block = ConfigBlock{
			Name:  "lan-port-shutdown",
			Lines: BuildInterfaceEthLines(req.Port, []string{LANPortShutdownLine(*req.Enabled)}),
			Risk:  ClassifyRisk("lan-port"),
			Keys:  []string{fmt.Sprintf("interface eth %d", req.Port)},
		}
	case "port_speed":
		if req.Speed == "" && req.Duplex == "" && req.Advertise == "" {
			writeSettingsError(w, http.StatusBadRequest, "at least one of speed, duplex, or advertise is required")
			return
		}
		var leaves []string
		if req.Speed != "" {
			if !slices.Contains(LANPortSpeedValues, req.Speed) {
				writeSettingsError(w, http.StatusBadRequest, "speed must be one of: "+strings.Join(LANPortSpeedValues, ", "))
				return
			}
			leaves = append(leaves, LANPortSpeedLine(req.Speed))
		}
		if req.Duplex != "" {
			if !slices.Contains(LANPortDuplexValues, req.Duplex) {
				writeSettingsError(w, http.StatusBadRequest, "duplex must be one of: "+strings.Join(LANPortDuplexValues, ", "))
				return
			}
			leaves = append(leaves, LANPortDuplexLine(req.Duplex))
		}
		if req.Advertise != "" {
			if !slices.Contains(LANPortAdvertiseValues, req.Advertise) {
				writeSettingsError(w, http.StatusBadRequest, "advertise must be one of: "+strings.Join(LANPortAdvertiseValues, ", "))
				return
			}
			leaves = append(leaves, LANPortAdvertiseLine(req.Advertise))
		}
		block = ConfigBlock{
			Name:  "lan-port-speed",
			Lines: BuildInterfaceEthLines(req.Port, leaves),
			Risk:  ClassifyRisk("lan-port"),
			Keys:  []string{fmt.Sprintf("interface eth %d", req.Port)},
		}
	case "vlan_ip":
		if req.IP == "" || req.Mask == "" {
			writeSettingsError(w, http.StatusBadRequest, "ip and mask are required")
			return
		}
		block = ConfigBlock{
			Name:  "vlan-ip",
			Lines: BuildInterfaceVLANLines(req.VLANID, []string{VLANIPLine(req.IP, req.Mask)}),
			Risk:  ClassifyRisk("vlan-ip"),
		}
	case "vlan_management_access":
		if req.ManagementAccess == nil {
			writeSettingsError(w, http.StatusBadRequest, "management_access is required")
			return
		}
		block = ConfigBlock{
			Name:  "vlan-management-access",
			Lines: BuildInterfaceVLANLines(req.VLANID, []string{VLANManagementAccessLine(*req.ManagementAccess)}),
			Risk:  ClassifyRisk("vlan-management-access"),
			Keys:  []string{key},
		}
	case "vlan_inter_vlan_routing":
		if req.InterVLANRouting == nil {
			writeSettingsError(w, http.StatusBadRequest, "inter_vlan_routing is required")
			return
		}
		// Enabled is the absence of a leaf, so a stanza pre-image cannot
		// undo this — the rollback needs the explicit inverse. See
		// ConfigBlock.Undo.
		block = ConfigBlock{
			Name:  "vlan-inter-vlan-routing",
			Lines: BuildInterfaceVLANLines(req.VLANID, []string{VLANInterVLANRoutingLine(*req.InterVLANRouting)}),
			Risk:  ClassifyRisk("vlan-inter-vlan-routing"),
			Keys:  []string{key},
			Undo:  BuildInterfaceVLANLines(req.VLANID, []string{VLANInterVLANRoutingLine(!*req.InterVLANRouting)}),
		}
	case "vlan_create":
		if req.IP == "" || req.Mask == "" {
			writeSettingsError(w, http.StatusBadRequest, "ip and mask are required")
			return
		}
		mgmt := req.ManagementAccess != nil && *req.ManagementAccess
		lines := BuildInterfaceVLANLines(req.VLANID, VLANCreateLines(req.IP, req.Mask, mgmt))
		if req.DHCP != nil && req.DHCP.valid() {
			pools, err := s.currentDHCPPools()
			if err != nil {
				writeDeviceError(w, err)
				return
			}
			netIP, err := NetworkAddress(req.IP, req.Mask)
			if err != nil {
				writeSettingsError(w, http.StatusBadRequest, err.Error())
				return
			}
			pool := nextAvailablePoolNumber(pools)
			lines = append(lines, BuildDHCPPoolLines(pool, DHCPPoolLines(DHCPScope{
				StartIP: req.DHCP.StartIP, EndIP: req.DHCP.EndIP,
				Router: req.DHCP.Router, DNS: req.DHCP.DNS, DNSSecondary: req.DHCP.DNSSecondary,
				Domain:    req.DHCP.Domain,
				LeaseDays: req.DHCP.LeaseDays, LeaseHours: req.DHCP.LeaseHours, LeaseMins: req.DHCP.LeaseMins,
				NetworkIP: netIP, NetworkMask: req.Mask, Options: req.DHCP.options(),
			}))...)
		}
		// Creating a new VLAN can't affect the session's existing
		// management access, so this is not routed through SafeApplier.
		block = ConfigBlock{Name: "vlan-create", Lines: lines, Risk: RiskNone}
	case "dhcp_scope":
		if req.DHCP == nil || !req.DHCP.valid() {
			writeSettingsError(w, http.StatusBadRequest, "start_ip, end_ip, router, and dns are required")
			return
		}
		cloud, pools, err := s.currentNetworkState()
		if err != nil {
			writeDeviceError(w, err)
			return
		}
		pool := poolNumberForVLAN(req.VLANID, cloud, pools)
		if pool == 0 {
			pool = nextAvailablePoolNumber(pools)
		}
		vlanIP, vlanMask := req.IP, req.Mask
		if vlanIP == "" || vlanMask == "" {
			for _, v := range cloud.LANInterfaces {
				if v.VLANID == req.VLANID {
					vlanIP, vlanMask = v.IPAddr, v.SubnetMask
				}
			}
		}
		netIP, err := NetworkAddress(vlanIP, vlanMask)
		if err != nil {
			writeSettingsError(w, http.StatusBadRequest, "could not determine this VLAN's network address: "+err.Error())
			return
		}
		block = ConfigBlock{
			Name: "dhcp-scope",
			Lines: BuildDHCPPoolLines(pool, DHCPPoolLines(DHCPScope{
				StartIP: req.DHCP.StartIP, EndIP: req.DHCP.EndIP,
				Router: req.DHCP.Router, DNS: req.DHCP.DNS, DNSSecondary: req.DHCP.DNSSecondary,
				Domain:    req.DHCP.Domain,
				LeaseDays: req.DHCP.LeaseDays, LeaseHours: req.DHCP.LeaseHours, LeaseMins: req.DHCP.LeaseMins,
				NetworkIP: netIP, NetworkMask: vlanMask, Options: req.DHCP.options(),
			})),
			Risk: RiskNone,
		}
	case "mac_bind_add", "mac_bind_delete":
		if req.MAC == "" || req.BindIP == "" {
			writeSettingsError(w, http.StatusBadRequest, "mac and bind_ip are required")
			return
		}
		cloud, pools, err := s.currentNetworkState()
		if err != nil {
			writeSettingsError(w, http.StatusBadGateway, err.Error())
			return
		}
		pool := poolNumberForVLAN(req.VLANID, cloud, pools)
		if pool == 0 {
			writeSettingsError(w, http.StatusBadRequest, "this VLAN has no DHCP pool, so it cannot hold reservations")
			return
		}
		var scope DHCPPoolSettings
		for _, p := range pools {
			if p.Pool == pool {
				scope = p
			}
		}

		if req.Action == "mac_bind_delete" {
			// The device matches the MAC case-sensitively on removal, so
			// the stored spelling is resolved here rather than trusting
			// whatever case the browser sent back.
			stored, ok := findBinding(scope.Bindings, req.MAC, req.BindIP)
			if !ok {
				writeSettingsError(w, http.StatusBadRequest, fmt.Sprintf("no reservation for %s on this VLAN", req.MAC))
				return
			}
			block = ConfigBlock{
				Name:  "dhcp-mac-binding",
				Lines: BuildDHCPPoolLines(pool, []string{DHCPNoBindLine(stored.MAC, stored.IP)}),
				Risk:  RiskNone,
			}
			break
		}

		var vlanIP, vlanMask string
		for _, v := range cloud.LANInterfaces {
			if v.VLANID == req.VLANID {
				vlanIP, vlanMask = v.IPAddr, v.SubnetMask
			}
		}
		if err := ValidateMACBinding(req.MAC, req.BindIP, vlanIP, vlanMask, scope, scope.Bindings); err != nil {
			writeSettingsError(w, http.StatusBadRequest, err.Error())
			return
		}
		block = ConfigBlock{
			Name:  "dhcp-mac-binding",
			Lines: BuildDHCPPoolLines(pool, []string{DHCPBindLine(req.MAC, req.BindIP)}),
			Risk:  RiskNone,
		}
	default:
		writeSettingsError(w, http.StatusBadRequest, "unknown action")
		return
	}

	outcome, err := s.safeApplier().Apply(block)
	if err != nil {
		writeDeviceError(w, err)
		return
	}
	writeJSON(w, outcome)
}

// findBinding locates an existing reservation by MAC (case-insensitively,
// since the browser round-trips whatever case it was shown) and returns it
// with the device's own spelling intact, which is what a removal line
// needs. The IP is checked too so a stale UI cannot delete a reservation
// that has since been re-pointed at a different address.
func findBinding(bindings []MACBinding, mac, ip string) (MACBinding, bool) {
	for _, b := range bindings {
		if strings.EqualFold(b.MAC, mac) && b.IP == ip {
			return b, true
		}
	}
	return MACBinding{}, false
}

func (s *Server) currentNetworkState() (CloudConfig, []DHCPPoolSettings, error) {
	cloud, err := FetchCloudConfig(s.Client, 20*time.Second)
	if err != nil {
		return CloudConfig{}, nil, err
	}
	cfgRaw, err := s.Client.Run("show config", 25*time.Second)
	if err != nil {
		return CloudConfig{}, nil, err
	}
	return cloud, ParseLANConfig(cfgRaw).DHCPPools, nil
}

func (s *Server) currentDHCPPools() ([]DHCPPoolSettings, error) {
	_, pools, err := s.currentNetworkState()
	return pools, err
}

// handleConfigWAN serves and edits WAN interfaces from cloud-json-config.
// Every write here is treated as RiskLockout: a wrong static IP, gateway,
// or monitor-hosts change on the wrong WAN can take the link down, and
// there's little value in trying to split hairs about which specific WAN
// field is "safe" versus not.
func (s *Server) handleConfigWAN(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleGetConfigWAN(w, r)
	case http.MethodPost:
		s.handlePostConfigWAN(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleGetConfigWAN(w http.ResponseWriter, _ *http.Request) {
	cloud, err := FetchCloudConfig(s.Client, 20*time.Second)
	if err != nil {
		writeDeviceError(w, err)
		return
	}
	cfgRaw, ok := s.cli(w, "show config", 25*time.Second)
	if !ok {
		return
	}
	writeJSON(w, map[string]any{
		"wans":  cloud.WANInterfaces,
		"ports": ParseLANConfig(cfgRaw).Ports, // includes non-WAN ports available to promote
		"pppoe": pppoeStatusByPort(cfgRaw),
	})
}

// PPPoEStatus is the read-side view of a WAN's "pppoe-server ..." leaves.
// Not modeled in cloud-json-config at all, so it's parsed straight from
// `show config`, keyed by eth port number.
type PPPoEStatus struct {
	Enabled     bool   `json:"enabled"`
	User        string `json:"user"`
	MTU         int    `json:"mtu"`
	MSSClamp    bool   `json:"mss_clamp"`
	ACName      string `json:"ac_name,omitempty"`
	ServiceName string `json:"service_name,omitempty"`
}

func pppoeStatusByPort(cfgRaw string) map[int]PPPoEStatus {
	tree := ParseBlockTree(cfgRaw)
	out := map[int]PPPoEStatus{}
	// Every eth block the device printed — port counts are model-specific
	// (six on an NSE3000, ten on an NSE4000), so no fixed range here.
	for _, eth := range ethInterfaceBlocks(tree) {
		n, blk := eth.port, eth.block
		if _, ok := blk.Leaf("pppoe-server enable"); !ok {
			continue
		}
		st := PPPoEStatus{
			Enabled:     true,
			User:        leafValue(blk, "pppoe-server user "),
			ACName:      leafValue(blk, "pppoe-server ac-name "),
			ServiceName: leafValue(blk, "pppoe-server service-name "),
		}
		if mtuLine, ok := blk.Leaf("pppoe-server mtu "); ok {
			fmt.Sscanf(strings.TrimPrefix(mtuLine, "pppoe-server mtu "), "%d", &st.MTU)
		}
		if _, ok := blk.Leaf("pppoe-server tcp-mss-clamp"); ok {
			st.MSSClamp = true
		}
		out[n] = st
	}
	return out
}

type wanRequest struct {
	Action       string   `json:"action"`
	Port         int      `json:"port"`
	Mode         string   `json:"mode"` // "static" | "dhcp"
	IP           string   `json:"ip"`
	Mask         string   `json:"mask"`
	Gateway      string   `json:"gateway"`
	Hosts        []string `json:"hosts"`
	Percent      int      `json:"percent"`
	UplinkMbps   int      `json:"uplink_mbps"`
	DownlinkMbps int      `json:"downlink_mbps"`
	Name         string   `json:"name"`     // for "enable" and "change_port"
	LBMode       string   `json:"lb_mode"`  // "shared" | "backup" | "disabled"
	Priority     *int     `json:"priority"` // backup-link-priority, only meaningful with lb_mode=backup
	NewPort      int      `json:"new_port"` // for "change_port": the eth port to move this WAN to

	// PPPoE fields, only used when Mode == "pppoe".
	PPPoEUser        string `json:"pppoe_user"`
	PPPoEPassword    string `json:"pppoe_password"`
	PPPoEMTU         int    `json:"pppoe_mtu"`
	PPPoEMSSClamp    bool   `json:"pppoe_mss_clamp"`
	PPPoEACName      string `json:"pppoe_ac_name"`
	PPPoEServiceName string `json:"pppoe_service_name"`

	// Connection Health fields, only used for action "connection_health".
	NumHostsFail      int `json:"num_hosts_fail"`
	FailureDetectTime int `json:"failure_detect_time"`
	PingInterval      int `json:"ping_interval"`
	PingTimeout       int `json:"ping_timeout"`
}

// currentLicense fetches and parses `show feature-license` directly
// (not cached — this only runs on the infrequent write paths that need to
// enforce a Security Plus gate server-side, as a backstop behind the
// frontend's own license-based UI gating).
func (s *Server) currentLicense() (FeatureLicense, error) {
	raw, err := s.Client.Run("show feature-license", 20*time.Second)
	if err != nil {
		return FeatureLicense{}, err
	}
	return ParseFeatureLicense(raw), nil
}

// wanIPModeLeaves validates and builds the leaves for a WAN IP mode
// (dhcp/static/pppoe), shared by the "ip_mode" action and by "change_port"
// when the swapped-to port should come up in a specific mode rather than
// the WANEnableLines default of DHCP. gwIndex is the physical port number
// the default-gateway line's trailing index should match (see
// WANStaticIPLines).
func wanIPModeLeaves(req wanRequest, gwIndex int) ([]string, error) {
	switch req.Mode {
	case "", "dhcp":
		return append([]string{PPPoEDisableLine()}, WANDHCPLines()...), nil
	case "static":
		if req.IP == "" || req.Mask == "" || req.Gateway == "" {
			return nil, fmt.Errorf("ip, mask, and gateway are required for static mode")
		}
		return append([]string{PPPoEDisableLine()}, WANStaticIPLines(req.IP, req.Mask, req.Gateway, gwIndex)...), nil
	case "pppoe":
		if req.PPPoEUser == "" || req.PPPoEPassword == "" {
			return nil, fmt.Errorf("pppoe_user and pppoe_password are required for PPPoE mode")
		}
		mtu := req.PPPoEMTU
		if mtu == 0 {
			mtu = 1492
		}
		if mtu < 500 || mtu > 1492 {
			return nil, fmt.Errorf("pppoe_mtu must be between 500 and 1492")
		}
		return PPPoEModeLines(PPPoEConfig{
			User: req.PPPoEUser, Password: req.PPPoEPassword, MTU: mtu, MSSClamp: req.PPPoEMSSClamp,
			ACName: req.PPPoEACName, ServiceName: req.PPPoEServiceName,
		}), nil
	default:
		return nil, fmt.Errorf("mode must be 'static', 'dhcp', or 'pppoe'")
	}
}

func (s *Server) handlePostConfigWAN(w http.ResponseWriter, r *http.Request) {
	if !isSameOrigin(r) {
		writeCrossOriginBlocked(w)
		return
	}
	var req wanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSettingsError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Port < 1 {
		writeSettingsError(w, http.StatusBadRequest, "port is required")
		return
	}
	key := fmt.Sprintf("interface eth %d", req.Port)

	var leaves []string
	switch req.Action {
	case "ip_mode":
		var err error
		leaves, err = wanIPModeLeaves(req, req.Port)
		if err != nil {
			writeSettingsError(w, http.StatusBadRequest, err.Error())
			return
		}
	case "change_port":
		if req.NewPort < 1 {
			writeSettingsError(w, http.StatusBadRequest, "new_port is required")
			return
		}
		if req.NewPort == req.Port {
			writeSettingsError(w, http.StatusBadRequest, "new_port must be different from the current port")
			return
		}
		if req.Name == "" {
			writeSettingsError(w, http.StatusBadRequest, "name is required")
			return
		}
		cfgRaw, ok := s.cli(w, "show config", 25*time.Second)
		if !ok {
			return
		}
		ipLeaves, err := wanIPModeLeaves(req, req.NewPort)
		if err != nil {
			writeSettingsError(w, http.StatusBadRequest, err.Error())
			return
		}
		newLeaves := WANPromoteLines(req.Name, currentPortVLAN(cfgRaw, req.NewPort), ipLeaves)
		if req.UplinkMbps > 0 && req.DownlinkMbps > 0 {
			newLeaves = append(newLeaves, WANBandwidthLines(req.UplinkMbps, req.DownlinkMbps)...)
		}
		lines := append(BuildInterfaceEthLines(req.Port, WANRevertToLANLines("1")), BuildInterfaceEthLines(req.NewPort, newLeaves)...)
		block := ConfigBlock{
			Name:  "wan-change-port",
			Lines: lines,
			Risk:  RiskLockout,
			Keys:  []string{fmt.Sprintf("interface eth %d", req.Port), fmt.Sprintf("interface eth %d", req.NewPort)},
		}
		outcome, err := s.safeApplier().Apply(block)
		if err != nil {
			writeDeviceError(w, err)
			return
		}
		writeJSON(w, outcome)
		return
	case "monitor_hosts":
		if len(req.Hosts) == 0 {
			writeSettingsError(w, http.StatusBadRequest, "hosts is required")
			return
		}
		leaves = []string{WANMonitorHostsLine(req.Hosts)}
	case "traffic_share":
		if req.Percent < 0 || req.Percent > 100 {
			writeSettingsError(w, http.StatusBadRequest, "percent must be between 0 and 100")
			return
		}
		leaves = []string{WANTrafficSharePercentageLine(req.Percent)}
	case "bandwidth":
		if req.UplinkMbps <= 0 || req.DownlinkMbps <= 0 {
			writeSettingsError(w, http.StatusBadRequest, "uplink_mbps and downlink_mbps are required")
			return
		}
		leaves = WANBandwidthLines(req.UplinkMbps, req.DownlinkMbps)
	case "enable":
		if req.Name == "" {
			writeSettingsError(w, http.StatusBadRequest, "name is required (e.g. \"wan3\")")
			return
		}
		cloud, err := FetchCloudConfig(s.Client, 20*time.Second)
		if err != nil {
			writeDeviceError(w, err)
			return
		}
		if len(cloud.WANInterfaces) >= 2 {
			lic, err := s.currentLicense()
			if err != nil {
				writeDeviceError(w, err)
				return
			}
			if !lic.OverlayWAN {
				writeSettingsError(w, http.StatusBadRequest, "adding a 3rd WAN port requires NSE Security Plus")
				return
			}
		}
		cfgRaw, ok := s.cli(w, "show config", 25*time.Second)
		if !ok {
			return
		}
		leaves = WANEnableLines(req.Name, currentPortVLAN(cfgRaw, req.Port))
		if req.UplinkMbps > 0 && req.DownlinkMbps > 0 {
			leaves = append(leaves, WANBandwidthLines(req.UplinkMbps, req.DownlinkMbps)...)
		}
	case "connection_health":
		if req.NumHostsFail < 1 {
			writeSettingsError(w, http.StatusBadRequest, "num_hosts_fail must be at least 1")
			return
		}
		if req.FailureDetectTime < 5 || req.FailureDetectTime > 60 {
			writeSettingsError(w, http.StatusBadRequest, "failure_detect_time must be between 5 and 60 seconds")
			return
		}
		if req.PingInterval < 2 || req.PingInterval > 10 {
			writeSettingsError(w, http.StatusBadRequest, "ping_interval must be between 2 and 10 seconds")
			return
		}
		if req.PingTimeout < 1 || req.PingTimeout > 10 {
			writeSettingsError(w, http.StatusBadRequest, "ping_timeout must be between 1 and 10 seconds")
			return
		}
		leaves = []string{
			WANNumHostsFailLine(req.NumHostsFail),
			WANPingFailureDetectTimeLine(req.FailureDetectTime),
			WANPingIntervalLine(req.PingInterval),
			WANPingTimeoutLine(req.PingTimeout),
		}
	case "load_balance_mode":
		switch req.LBMode {
		case "shared", "backup", "disabled":
		default:
			writeSettingsError(w, http.StatusBadRequest, "lb_mode must be 'shared', 'backup', or 'disabled'")
			return
		}
		leaves = []string{WANLoadBalanceModeLine(req.LBMode)}
		if req.LBMode == "backup" && req.Priority != nil {
			leaves = append(leaves, WANBackupLinkPriorityLine(*req.Priority))
		}
	default:
		writeSettingsError(w, http.StatusBadRequest, "unknown action")
		return
	}

	block := ConfigBlock{
		Name:  "wan-" + req.Action,
		Lines: BuildInterfaceEthLines(req.Port, leaves),
		Risk:  ClassifyRisk("wan"),
		Keys:  []string{key},
	}
	outcome, err := s.safeApplier().Apply(block)
	if err != nil {
		writeDeviceError(w, err)
		return
	}
	writeJSON(w, outcome)
}
