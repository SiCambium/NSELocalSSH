package nse

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"net/url"
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

	applierOnce sync.Once
	applier     *SafeApplier
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
		"version":         ParseVersion(ver),
		"clock":           ParseClock(clock),
		"remote":          ParseRemote(remote).Summary,
		"memory":          ParseMemory(mem),
		"cpu":             ParseTop(top),
		"wan_throughput":  wanThroughput(rates),
		"rates_ready":     sampled,
		"sample_interval": intervalMs,
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
	live := ReadPrefs(s.prefsFile()).LiveConntrack
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
		"summary":      ParseConntrack(summary),
		"flows":        parsed,
		"live_enabled": live,
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

func (s *Server) handleTraffic(w http.ResponseWriter, _ *http.Request) {
	apps, ok := s.cli(w, "show application-statistics by-application", 30*time.Second)
	if !ok {
		return
	}
	cats, ok := s.cli(w, "show application-statistics by-category", 30*time.Second)
	if !ok {
		return
	}
	counters, ok := s.cli(w, "show filter global-filter", 20*time.Second)
	if !ok {
		return
	}
	rules, ok := s.cli(w, "show config filter", 20*time.Second)
	if !ok {
		return
	}
	writeJSON(w, map[string]any{
		"by_application":  ParseAppStats(apps),
		"by_category":     ParseAppStats(cats),
		"filter_counters": ParseFilterCounters(counters),
		"filter_rules":    ParseConfigFilter(rules),
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
	ts, ok := s.cli(w, "show tailscale status", 20*time.Second)
	if !ok {
		return
	}
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
		"tailscale":     ParseTailscaleStatus(ts),
		"vpn":           []VPNSessions{wgS, l2S, ipS},
		"starlink_ping": ParsePing(pingRaw),
		"interfaces":    ParseInterfaceBrief(ifaces),
		"wan_dhcp":      ParseIPDHCP(dhcp),
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
	mux.HandleFunc("/api/settings", s.handleSettings)
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
	mux.HandleFunc("/api/traffic", s.handleTraffic)
	mux.HandleFunc("/api/tunnels", s.handleTunnels)
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
