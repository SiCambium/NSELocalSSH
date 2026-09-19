package nse

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"
)

type Server struct {
	Client       *Client
	Static       fs.FS
	SettingsPath string
	SkipConnect  bool

	sampleMu     sync.Mutex
	lastIfaces   []IfconfigIface
	lastSample   time.Time
	lastRates    []Throughput
	lastInterval time.Duration

	wanPortMu  sync.Mutex
	wanPortSet map[string]bool
	wanPortAt  time.Time

	threatMu    sync.Mutex
	threatCache ThreatSummary
	threatAt    time.Time

	identityMu    sync.Mutex
	identityCache Version
	identityAt    time.Time

	applierOnce sync.Once
	applier     *SafeApplier

	ipOrgCacheOnce sync.Once
	ipOrgCache     *ipOrgCache
}

// ThreatSummary is the small, secret-free subset of Threat Protection
// state shown on the Overview tab — deliberately just the fields already
// exposed read-only by /api/config/threat, no oinkcode or category list.
type ThreatSummary struct {
	Enabled        bool   `json:"enabled"`
	Mode           string `json:"mode"`
	RuleType       string `json:"rule_type"`
	RuleSet        string `json:"rule_set"`
	AutoUpdate     bool   `json:"auto_update"`
	UpdateInterval string `json:"update_interval"`
}

// threatSummary is cached for 30s for the same reason as wanPorts(): the
// Overview tab polls every few seconds, and this data rarely changes.
// Returns the last-known value (zero value if never fetched successfully)
// on failure so a transient error doesn't blank the dashboard.
func (s *Server) threatSummary() ThreatSummary {
	s.threatMu.Lock()
	defer s.threatMu.Unlock()
	if time.Since(s.threatAt) < 30*time.Second {
		return s.threatCache
	}
	cfg, err := FetchCloudConfig(s.Client, 10*time.Second)
	if err != nil {
		return s.threatCache
	}
	s.threatCache = ThreatSummary{
		Enabled:        cfg.IPS,
		Mode:           cfg.IPSMode,
		RuleType:       cfg.IPSRuleType,
		RuleSet:        cfg.IPSRuleSet,
		AutoUpdate:     cfg.IPSAutoUpdate,
		UpdateInterval: cfg.IPSUpdateInterval,
	}
	s.threatAt = time.Now()
	return s.threatCache
}

// wanPorts returns the set of CLI port names ("eth1") currently configured
// as WAN, keyed from cloud-json-config's wan_interfaces — the same source
// of truth the Configuration > WAN section reads. This is which physical
// port carries a WAN role, a static fact about the port's configuration,
// not something that should be guessed at from whether it happens to have
// a live IP on any given poll (a WAN port with DHCP still negotiating, or a
// disconnected WAN cable, has no IP yet but is still WAN). Cached for 30s
// since it rarely changes and every dashboard poll would otherwise cost an
// extra serialized SSH round-trip. Returns the last-known set (possibly
// nil) on fetch failure so a transient error doesn't blank the dashboard.
func (s *Server) wanPorts() map[string]bool {
	s.wanPortMu.Lock()
	defer s.wanPortMu.Unlock()
	if s.wanPortSet != nil && time.Since(s.wanPortAt) < 30*time.Second {
		return s.wanPortSet
	}
	cfg, err := FetchCloudConfig(s.Client, 10*time.Second)
	if err != nil {
		return s.wanPortSet
	}
	set := make(map[string]bool, len(cfg.WANInterfaces))
	for _, w := range cfg.WANInterfaces {
		if w.LANIntf != "" {
			set[w.LANIntf] = true
		}
	}
	s.wanPortSet = set
	s.wanPortAt = time.Now()
	return set
}

// safeApplier lazily constructs the server's SafeApplier so that existing
// Server{...} struct literals (main.go) don't need a constructor change.
func (s *Server) safeApplier() *SafeApplier {
	s.applierOnce.Do(func() {
		s.applier = NewSafeApplier(s.Client)
	})
	return s.applier
}

// SwitchDevice repoints the shared client at a different device, after
// discarding every piece of state that belonged to the previous one.
//
// Nothing on Server is device-agnostic except the IP-to-org lookup cache
// (which is keyed by public IP, not by device), so all of it has to go:
// the throughput sampler in particular would otherwise compute its first
// rate after a switch by subtracting one device's byte counters from
// another's, producing garbage.
//
// A change that is still provisional blocks the switch outright rather
// than being discarded. Its rollback pre-image is the *old* device's
// config, and SafeApplier's expiry loop replays pre-images through
// whatever the shared client currently points at — so letting the switch
// through would eventually write one site's configuration onto another.
// Confirming it, or simply waiting out the short window, clears the way.
func (s *Server) SwitchDevice(cfg Config) error {
	if a := s.safeApplier(); a.PendingCount() > 0 {
		return fmt.Errorf("a configuration change on the current device is still awaiting confirmation; confirm it or wait for it to roll back before switching")
	}

	s.sampleMu.Lock()
	s.lastIfaces, s.lastRates, s.lastSample, s.lastInterval = nil, nil, time.Time{}, 0
	s.sampleMu.Unlock()

	s.wanPortMu.Lock()
	s.wanPortSet, s.wanPortAt = nil, time.Time{}
	s.wanPortMu.Unlock()

	s.threatMu.Lock()
	s.threatCache, s.threatAt = ThreatSummary{}, time.Time{}
	s.threatMu.Unlock()

	if s.SkipConnect {
		s.Client.mu.Lock()
		s.Client.Cfg = cfg
		s.Client.mu.Unlock()
		return nil
	}
	return s.Client.ApplyConfig(cfg)
}

func (s *Server) cli(w http.ResponseWriter, cmd string, timeout time.Duration) (string, bool) {
	out, err := s.Client.Run(cmd, timeout)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]string{"detail": err.Error()})
		return "", false
	}
	return out, true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// isSameOrigin reports whether a state-changing request came from this
// server's own page rather than some other site or tab. Browsers attach
// Origin (and, failing that, Referer) truthfully and a page cannot forge
// them, so this blocks cross-site requests that would otherwise be able to
// silently repoint the device connection (e.g. via /api/settings) using
// credentials already saved in this app. Requests with neither header
// (non-browser clients hitting the API directly) are let through, since
// forging headers is trivial for those and they're outside the CSRF threat
// model this defends against.
func isSameOrigin(r *http.Request) bool {
	if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" {
		return sfs == "same-origin" || sfs == "none"
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		return err == nil && u.Host == r.Host
	}
	if referer := r.Header.Get("Referer"); referer != "" {
		u, err := url.Parse(referer)
		return err == nil && u.Host == r.Host
	}
	return true
}

func writeCrossOriginBlocked(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]string{"detail": "cross-origin request blocked"})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]string{"host": s.Client.Cfg.Host, "user": s.Client.Cfg.User})
}

// handleIdentity answers "which device is this, and is it answering?" in
// one cheap round trip.
//
// Both facts were previously only learnable from the Status page — the
// header's model name came from the overview/details payloads and its
// connection dot from their polling — so opening or reloading straight
// into Configuration left the header showing a generic name and an
// uncontacted-grey dot until the user happened to visit Status. /api/health
// cannot fill the gap: it echoes the configured host without touching the
// device, so it proves nothing about reachability.
//
// This is one `show version`, unlike the overview payload's several
// commands, and the answer is cached because a model and serial do not
// change. The cache is deliberately short so the endpoint keeps working as
// a liveness check rather than answering from memory long after the device
// has gone away.
func (s *Server) handleIdentity(w http.ResponseWriter, _ *http.Request) {
	s.identityMu.Lock()
	if !s.identityAt.IsZero() && time.Since(s.identityAt) < 15*time.Second {
		cached := s.identityCache
		s.identityMu.Unlock()
		writeJSON(w, map[string]any{"version": cached})
		return
	}
	s.identityMu.Unlock()

	raw, ok := s.cli(w, "show version", 20*time.Second)
	if !ok {
		return
	}
	version := ParseVersion(raw)

	s.identityMu.Lock()
	s.identityCache, s.identityAt = version, time.Now()
	s.identityMu.Unlock()

	writeJSON(w, map[string]any{"version": version})
}

func (s *Server) withRates(ifaces []IfconfigIface) (rates []Throughput, sampled bool, intervalMs int64) {
	now := time.Now()
	s.sampleMu.Lock()
	defer s.sampleMu.Unlock()
	if !s.lastSample.IsZero() {
		dt := now.Sub(s.lastSample)
		if dt < 400*time.Millisecond {
			if s.lastRates == nil {
				s.lastRates = []Throughput{}
			}
			return s.lastRates, len(s.lastRates) > 0, s.lastInterval.Milliseconds()
		}
		rates = RatesFromSamples(s.lastIfaces, ifaces, dt)
		s.lastRates = rates
		s.lastInterval = dt
		sampled = true
		intervalMs = dt.Milliseconds()
	}
	s.lastIfaces = ifaces
	s.lastSample = now
	if rates == nil {
		rates = []Throughput{}
	}
	return rates, sampled, intervalMs
}

func wanThroughput(rows []Throughput) []Throughput {
	var out []Throughput
	for _, r := range rows {
		if r.Role == "wan" {
			out = append(out, r)
		}
	}
	if out == nil {
		return []Throughput{}
	}
	return out
}

func (s *Server) handleOverview(w http.ResponseWriter, _ *http.Request) {
	ver, ok := s.cli(w, "show version", 20*time.Second)
	if !ok {
		return
	}
	clock, ok := s.cli(w, "show clock", 20*time.Second)
	if !ok {
		return
	}
	remote, ok := s.cli(w, "show remote", 20*time.Second)
	if !ok {
		return
	}
	mem, ok := s.cli(w, "service show memory", 20*time.Second)
	if !ok {
		return
	}
	top, ok := s.cli(w, "service show top", 20*time.Second)
	if !ok {
		return
	}
	ifc, ok := s.cli(w, "service show ifconfig", 20*time.Second)
	if !ok {
		return
	}
	ifaces := ParseIfconfig(ifc, s.wanPorts())
	rates, sampled, intervalMs := s.withRates(ifaces)
	writeJSON(w, map[string]any{
		"version":           ParseVersion(ver),
		"clock":             ParseClock(clock),
		"remote":            ParseRemote(remote).Summary,
		"memory":            ParseMemory(mem),
		"cpu":               ParseTop(top),
		"wan_throughput":    wanThroughput(rates),
		"rates_ready":       sampled,
		"sample_interval":   intervalMs,
		"threat_protection": s.threatSummary(),
	})
}

func (s *Server) handleDetails(w http.ResponseWriter, _ *http.Request) {
	ver, ok := s.cli(w, "show version", 20*time.Second)
	if !ok {
		return
	}
	clock, ok := s.cli(w, "show clock", 20*time.Second)
	if !ok {
		return
	}
	mgmt, ok := s.cli(w, "show management", 20*time.Second)
	if !ok {
		return
	}
	remote, ok := s.cli(w, "show remote", 20*time.Second)
	if !ok {
		return
	}
	df, ok := s.cli(w, "service show df", 20*time.Second)
	if !ok {
		return
	}
	power, ok := s.cli(w, "show power", 20*time.Second)
	if !ok {
		return
	}
	usb, ok := s.cli(w, "show usb", 20*time.Second)
	if !ok {
		return
	}
	writeJSON(w, map[string]any{
		"version":    ParseVersion(ver),
		"clock":      ParseClock(clock),
		"management": ParseManagement(mgmt),
		"remote":     ParseRemote(remote),
		"disks":      ParseDF(df),
		"power":      ParsePower(power),
		"usb":        ParseUSB(usb),
	})
}

func (s *Server) handleMemory(w http.ResponseWriter, _ *http.Request) {
	mem, ok := s.cli(w, "service show memory", 20*time.Second)
	if !ok {
		return
	}
	writeJSON(w, map[string]any{"memory": ParseMemory(mem)})
}

func (s *Server) handleThroughput(w http.ResponseWriter, _ *http.Request) {
	ifc, ok := s.cli(w, "service show ifconfig", 20*time.Second)
	if !ok {
		return
	}
	ifaces := ParseIfconfig(ifc, s.wanPorts())
	rates, sampled, intervalMs := s.withRates(ifaces)
	writeJSON(w, map[string]any{
		"interfaces":      ifaces,
		"throughput":      rates,
		"rates_ready":     sampled,
		"sample_interval": intervalMs,
	})
}

func (s *Server) handleConntrack(w http.ResponseWriter, _ *http.Request) {
	summary, ok := s.cli(w, "service show conntrack", 20*time.Second)
	if !ok {
		return
	}
	prefs := ReadPrefs(s.prefsFile())
	live := prefs.LiveConntrack
	parsed := []ConntrackFlow{}
	if live {
		flows, ok := s.cli(w, "show conntrack", 30*time.Second)
		if !ok {
			return
		}
		parsed = ParseConntrackFlows(flows)
		if parsed == nil {
			parsed = []ConntrackFlow{}
		}
	}
	writeJSON(w, map[string]any{
		"summary":           ParseConntrack(summary),
		"flows":             parsed,
		"live_enabled":      live,
		"ip_lookup_enabled": prefs.IPLookup,
	})
}

func (s *Server) handleInterfaces(w http.ResponseWriter, _ *http.Request) {
	ifaces, ok := s.cli(w, "show interface brief", 20*time.Second)
	if !ok {
		return
	}
	pppoe, ok := s.cli(w, "show pppoe", 20*time.Second)
	if !ok {
		return
	}
	power, ok := s.cli(w, "show power", 20*time.Second)
	if !ok {
		return
	}
	usb, ok := s.cli(w, "show usb", 20*time.Second)
	if !ok {
		return
	}
	dhcp, ok := s.cli(w, "show ip dhcp", 20*time.Second)
	if !ok {
		return
	}
	writeJSON(w, map[string]any{
		"interfaces": ParseInterfaceBrief(ifaces),
		"pppoe":      ParsePPPoE(pppoe),
		"power":      ParsePower(power),
		"usb":        ParseUSB(usb),
		"wan_dhcp":   ParseIPDHCP(dhcp),
	})
}

func (s *Server) handleRouting(w http.ResponseWriter, _ *http.Request) {
	routes, ok := s.cli(w, "show route", 20*time.Second)
	if !ok {
		return
	}
	v6, ok := s.cli(w, "show ipv6 route", 20*time.Second)
	if !ok {
		return
	}
	arp, ok := s.cli(w, "show arp", 20*time.Second)
	if !ok {
		return
	}
	writeJSON(w, map[string]any{
		"routes":      ParseRoute(routes),
		"ipv6_routes": ParseRoute(v6),
		"arp":         ParseARP(arp),
	})
}

func (s *Server) handleDHCP(w http.ResponseWriter, _ *http.Request) {
	var pools []DHCPPool
	for i := 1; i <= 8; i++ {
		raw, ok := s.cli(w, "show dhcp-pool "+itoa(i), 20*time.Second)
		if !ok {
			return
		}
		if p, found := ParseDHCPPool(raw, i); found {
			pools = append(pools, p)
		}
	}
	wan, ok := s.cli(w, "show ip dhcp", 20*time.Second)
	if !ok {
		return
	}
	if pools == nil {
		pools = []DHCPPool{}
	}
	cfgRaw, ok := s.cli(w, "show config", 25*time.Second)
	if !ok {
		return
	}
	lan := ParseLANConfig(cfgRaw)
	writeJSON(w, map[string]any{
		"pools":         pools,
		"wan_client":    ParseIPDHCP(wan),
		"authoritative": lan.Authoritative,
		"pool_config":   lan.DHCPPools,
		"bindings":      lan.Bindings,
	})
}

func (s *Server) handleNeighbors(w http.ResponseWriter, _ *http.Request) {
	lldp, ok := s.cli(w, "show lldp neighbors", 20*time.Second)
	if !ok {
		return
	}
	cambium, ok := s.cli(w, "show cambium", 20*time.Second)
	if !ok {
		return
	}
	remote, ok := s.cli(w, "show remote", 20*time.Second)
	if !ok {
		return
	}
	writeJSON(w, map[string]any{
		"lldp":    ParseLLDPNeighbors(lldp),
		"cambium": ParseCambium(cambium),
		"remote":  ParseRemote(remote),
	})
}

func (s *Server) handleDevices(w http.ResponseWriter, _ *http.Request) {
	raw, ok := s.cli(w, "show connected-clients", 20*time.Second)
	if !ok {
		return
	}
	writeJSON(w, map[string]any{
		"clients": orEmpty(ParseConnectedClients(raw)),
	})
}

func (s *Server) handleTraffic(w http.ResponseWriter, _ *http.Request) {
	apps, ok := s.cli(w, "show application-statistics by-application", 30*time.Second)
	if !ok {
		return
	}
	cats, ok := s.cli(w, "show application-statistics by-category", 30*time.Second)
	if !ok {
		return
	}
	writeJSON(w, map[string]any{
		"by_application": ParseAppStats(apps),
		"by_category":    ParseAppStats(cats),
	})
}

func (s *Server) handleEvents(w http.ResponseWriter, _ *http.Request) {
	raw, ok := s.cli(w, "show events", 20*time.Second)
	if !ok {
		return
	}
	writeJSON(w, map[string]any{"events": ParseEvents(raw)})
}

func (s *Server) handleTunnels(w http.ResponseWriter, _ *http.Request) {
	cfgRaw, ok := s.cli(w, "show config", 25*time.Second)
	if !ok {
		return
	}
	cfg := ParseTunnelConfig(cfgRaw)
	wg, ok := s.cli(w, "show vpn-sessions wireguard", 20*time.Second)
	if !ok {
		return
	}
	l2tp, ok := s.cli(w, "show vpn-sessions l2tp", 20*time.Second)
	if !ok {
		return
	}
	ipsec, ok := s.cli(w, "show vpn-sessions ipsec", 20*time.Second)
	if !ok {
		return
	}
	ifaces, ok := s.cli(w, "show interface brief", 20*time.Second)
	if !ok {
		return
	}
	dhcp, ok := s.cli(w, "show ip dhcp", 20*time.Second)
	if !ok {
		return
	}
	dishIP := cfg.Starlink.DishIP
	if dishIP == "" {
		dishIP = "192.168.100.1"
	}
	pingRaw, ok := s.cli(w, "ping "+dishIP, 25*time.Second)
	if !ok {
		return
	}
	wgS, l2S, ipS := ParseVPNSessions(wg), ParseVPNSessions(l2tp), ParseVPNSessions(ipsec)
	wgS.Kind, l2S.Kind, ipS.Kind = "wireguard", "l2tp", "ipsec"
	writeJSON(w, map[string]any{
		"config":        cfg,
		"vpn":           []VPNSessions{wgS, l2S, ipS},
		"starlink_ping": ParsePing(pingRaw),
		"interfaces":    ParseInterfaceBrief(ifaces),
		"wan_dhcp":      ParseIPDHCP(dhcp),
	})
}

// handleTailscale serves Tailscale/Tailnet status on its own tab,
// split out from handleTunnels per the user's request to keep it
// separate from the client-VPN/Starlink "VPN" tab.
func (s *Server) handleTailscale(w http.ResponseWriter, _ *http.Request) {
	cfgRaw, ok := s.cli(w, "show config", 25*time.Second)
	if !ok {
		return
	}
	cfg := ParseTunnelConfig(cfgRaw)
	ts, ok := s.cli(w, "show tailscale status", 20*time.Second)
	if !ok {
		return
	}
	writeJSON(w, map[string]any{
		"config": cfg.Tailscale,
		"peers":  ParseTailscaleStatus(ts),
	})
}

// handleFirewallCounters serves per-rule hit counters from "show
// counters outbound_firewall" — the same data as cnMaestro's Firewall
// Counters > Outbound Firewall table (RuleId/Name/Comment/Packets/Bytes,
// including the device's own human-readable rule summary as Comment).
func (s *Server) handleFirewallCounters(w http.ResponseWriter, _ *http.Request) {
	countersRaw, ok := s.cli(w, "show counters outbound_firewall", 20*time.Second)
	if !ok {
		return
	}
	writeJSON(w, map[string]any{
		"outbound_firewall": ParseOutboundFirewallCounters(countersRaw),
	})
}

func (s *Server) handleVLANs(w http.ResponseWriter, _ *http.Request) {
	cfgRaw, ok := s.cli(w, "show config", 25*time.Second)
	if !ok {
		return
	}
	ifaces, ok := s.cli(w, "show interface brief", 20*time.Second)
	if !ok {
		return
	}
	lan := ParseLANConfig(cfgRaw)
	writeJSON(w, map[string]any{
		"vlans":      lan.VLANs,
		"ports":      lan.Ports,
		"interfaces": ParseInterfaceBrief(ifaces),
	})
}

func (s *Server) handleConfig(w http.ResponseWriter, _ *http.Request) {
	raw, ok := s.cli(w, "show config", 25*time.Second)
	if !ok {
		return
	}
	writeJSON(w, map[string]any{
		"config": SanitizeCLIOutput(stripCLI(raw, "show config")),
	})
}

func itoa(i int) string {
	return strconv.Itoa(i)
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/identity", s.handleIdentity)
	mux.HandleFunc("/api/settings", s.handleSettings)
	mux.HandleFunc("/api/iplookup", s.handleIPLookup)
	mux.HandleFunc("/api/overview", s.handleOverview)
	mux.HandleFunc("/api/details", s.handleDetails)
	mux.HandleFunc("/api/throughput", s.handleThroughput)
	mux.HandleFunc("/api/memory", s.handleMemory)
	mux.HandleFunc("/api/conntrack", s.handleConntrack)
	mux.HandleFunc("/api/interfaces", s.handleInterfaces)
	mux.HandleFunc("/api/routing", s.handleRouting)
	mux.HandleFunc("/api/dhcp", s.handleDHCP)
	mux.HandleFunc("/api/vlans", s.handleVLANs)
	mux.HandleFunc("/api/neighbors", s.handleNeighbors)
	mux.HandleFunc("/api/devices", s.handleDevices)
	mux.HandleFunc("/api/traffic", s.handleTraffic)
	mux.HandleFunc("/api/tunnels", s.handleTunnels)
	mux.HandleFunc("/api/tailscale", s.handleTailscale)
	mux.HandleFunc("/api/firewallcounters", s.handleFirewallCounters)
	mux.HandleFunc("/api/events", s.handleEvents)
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/debug", s.handleDebug)
	mux.HandleFunc("/api/license", s.handleLicense)
	mux.HandleFunc("/api/config/confirm", s.handleConfigConfirm)
	mux.HandleFunc("/api/config/network", s.handleConfigNetwork)
	mux.HandleFunc("/api/config/wan", s.handleConfigWAN)
	mux.HandleFunc("/api/config/management", s.handleConfigManagement)
	mux.HandleFunc("/api/config/dns", s.handleConfigDNS)
	mux.HandleFunc("/api/config/threat", s.handleConfigThreat)
	mux.HandleFunc("/api/config/vpn", s.handleConfigVPN)
	mux.HandleFunc("/api/config/firewall", s.handleConfigFirewall)
	mux.HandleFunc("/api/config/groups", s.handleConfigGroups)
	mux.HandleFunc("/api/profile/export", s.handleProfileExport)
	static, err := fs.Sub(s.Static, "static")
	if err != nil {
		static = s.Static
	}
	// Development only: serve the UI from disk and stream reload events so
	// an edit to web/static is visible without a rebuild. See devreload.go
	// for why this is env-gated.
	if dir := devStaticDir(); dir != "" {
		static = os.DirFS(dir)
		s.registerDevReload(mux, dir)
		log.Printf("dev mode: serving UI from %s with live reload", dir)
	}
	fileServer := http.FileServer(http.FS(static))
	mux.Handle("/static/", http.StripPrefix("/static/", fileServer))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.ServeFileFS(w, r, static, "index.html")
	})
	return mux
}
