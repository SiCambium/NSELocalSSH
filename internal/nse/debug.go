package nse

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type DebugArg string

const (
	DebugArgNone   DebugArg = ""
	DebugArgHost   DebugArg = "host"
	DebugArgDaemon DebugArg = "daemon"
	DebugArgPool   DebugArg = "pool"
)

type DebugCommand struct {
	ID       string        `json:"id"`
	Label    string        `json:"label"`
	Group    string        `json:"group"`
	Command  string        `json:"command"`
	Arg      DebugArg      `json:"arg,omitempty"`
	Note     string        `json:"note,omitempty"`
	Heavy    bool          `json:"heavy,omitempty"`
	Sanitize bool          `json:"-"`
	Timeout  time.Duration `json:"-"`
}

var debugHostRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.:_-]*$`)
var debugPoolRe = regexp.MustCompile(`^([1-9]|1[0-6])$`)

var debugDaemons = []string{
	"device-agent", "dpid", "dpistatsd", "infrad", "mdnsd", "messages", "nfq_agent",
	"rfmd", "rca-agent", "scmd", "troubleshooting", "wmd", "xrp", "xwfd", "sysmond",
	"utm", "godns", "wanlb", "vpn", "radius-server", "rsync", "grub2", "goavc1",
	"connectedclients", "radiusd", "tailscaled",
}

func debugCommands() []DebugCommand {
	sec := func(id, label, group, cmd, note string, timeout time.Duration, heavy, sanitize bool, arg DebugArg) DebugCommand {
		if timeout == 0 {
			timeout = 20 * time.Second
		}
		return DebugCommand{
			ID: id, Label: label, Group: group, Command: cmd, Arg: arg,
			Note: note, Heavy: heavy, Sanitize: sanitize, Timeout: timeout,
		}
	}
	return []DebugCommand{
		sec("show-power", "show power", "Device", "show power", "PoE / power platform.", 0, false, false, DebugArgNone),
		sec("show-management", "show management", "Device", "show management", "HTTP/HTTPS/SSH/Telnet and cnMaestro.", 0, false, false, DebugArgNone),
		sec("show-time", "show time", "Device", "show time", "", 0, false, false, DebugArgNone),
		sec("show-timezone", "show timezone", "Device", "show timezone", "", 0, false, false, DebugArgNone),
		sec("show-clock", "show clock", "Device", "show clock", "", 0, false, false, DebugArgNone),
		sec("show-version", "show version", "Device", "show version", "", 0, false, false, DebugArgNone),
		sec("show-usb", "show usb", "Device", "show usb", "", 0, false, false, DebugArgNone),
		sec("show-cambium", "show cambium", "Device", "show cambium", "", 0, false, false, DebugArgNone),
		sec("show-remote", "show remote", "Device", "show remote", "cnMaestro connection history.", 0, false, false, DebugArgNone),

		sec("show-lldp-detail", "show lldp neighbors detail", "Neighbors", "show lldp neighbors detail", "", 0, false, false, DebugArgNone),
		sec("show-lldp-ifaces", "show lldp interfaces", "Neighbors", "show lldp interfaces", "", 0, false, false, DebugArgNone),
		sec("show-lldp", "show lldp neighbors", "Neighbors", "show lldp neighbors", "", 0, false, false, DebugArgNone),

		sec("show-ipv6-route", "show ipv6 route", "Routing", "show ipv6 route", "Often empty if IPv6 is unused.", 0, false, false, DebugArgNone),
		sec("show-route", "show route", "Routing", "show route", "", 0, false, false, DebugArgNone),
		sec("service-show-route", "service show route", "Routing", "service show route", "Kernel/service view of routes.", 0, false, false, DebugArgNone),
		sec("show-arp", "show arp", "Routing", "show arp", "", 0, false, false, DebugArgNone),

		sec("show-vpn", "show vpn", "VPN / tunnels", "show vpn", "Often returns empty JSON when no clients are up.", 0, false, false, DebugArgNone),
		sec("show-vpn-sessions", "show vpn-sessions", "VPN / tunnels", "show vpn-sessions", "", 0, false, false, DebugArgNone),
		sec("show-vpn-wg", "show vpn-sessions wireguard", "VPN / tunnels", "show vpn-sessions wireguard", "", 0, false, false, DebugArgNone),
		sec("show-vpn-l2tp", "show vpn-sessions l2tp", "VPN / tunnels", "show vpn-sessions l2tp", "", 0, false, false, DebugArgNone),
		sec("show-vpn-ipsec", "show vpn-sessions ipsec", "VPN / tunnels", "show vpn-sessions ipsec", "", 0, false, false, DebugArgNone),
		sec("show-tailscale-status", "show tailscale status", "VPN / tunnels", "show tailscale status", "", 0, false, false, DebugArgNone),

		sec("show-filter", "show filter", "Firewall", "show filter", "", 0, false, false, DebugArgNone),
		sec("show-filter-global", "show filter global-filter", "Firewall", "show filter global-filter", "", 0, false, false, DebugArgNone),
		sec("show-config-filter", "show config filter", "Firewall", "show config filter", "", 0, false, false, DebugArgNone),

		sec("show-ip-dhcp", "show ip dhcp", "DHCP", "show ip dhcp", "WAN DHCP client lease.", 0, false, false, DebugArgNone),
		sec("show-dhcp-pool", "show dhcp-pool <n>", "DHCP", "show dhcp-pool %s", "Live leases for one pool.", 0, false, false, DebugArgPool),

		sec("show-pppoe", "show pppoe", "Interfaces", "show pppoe", "", 0, false, false, DebugArgNone),
		sec("show-iface-brief", "show interface brief", "Interfaces", "show interface brief", "", 0, false, false, DebugArgNone),
		sec("service-show-ethtool", "service show ethtool", "Interfaces", "service show ethtool", "Per-NIC driver details.", 25*time.Second, true, false, DebugArgNone),

		sec("service-show-flash", "service show flash", "Diagnostics", "service show flash", "Flash partitions.", 0, false, false, DebugArgNone),
		sec("service-show-df", "service show df", "Diagnostics", "service show df", "", 0, false, false, DebugArgNone),
		sec("service-show-memory", "service show memory", "Diagnostics", "service show memory", "", 0, false, false, DebugArgNone),
		sec("service-show-ip", "service show ip", "Diagnostics", "service show ip", "iperf daemon status.", 0, false, false, DebugArgNone),
		sec("service-show-conntrack", "service show conntrack", "Diagnostics", "service show conntrack", "", 0, false, false, DebugArgNone),
		sec("show-conntrack", "show conntrack", "Diagnostics", "show conntrack", "Live connections. Can be large.", 30*time.Second, true, false, DebugArgNone),
		sec("service-show-dmesg", "service show dmesg", "Diagnostics", "service show dmesg", "Kernel log. Can be large.", 30*time.Second, true, false, DebugArgNone),
		sec("service-show-debug-logs", "service show debug-logs", "Diagnostics", "service show debug-logs", "Lists daemon log names.", 0, false, false, DebugArgNone),
		sec("service-show-debug-logs-daemon", "service show debug-logs <daemon>", "Diagnostics", "service show debug-logs %s", "vpn, tailscaled, wanlb, and others.", 25*time.Second, true, false, DebugArgDaemon),
		sec("nslookup", "nslookup <host>", "Diagnostics", "nslookup %s", "DNS lookup via the NSE resolvers.", 0, false, false, DebugArgHost),
		sec("ping", "ping <host>", "Diagnostics", "ping %s", "ICMP from the NSE.", 25*time.Second, false, false, DebugArgHost),
		sec("show-config", "show config (secrets stripped)", "Diagnostics", "show config", "Running CLI config. Passwords and keys are redacted.", 25*time.Second, true, true, DebugArgNone),
		sec("show-events", "show events", "Diagnostics", "show events", "", 0, false, false, DebugArgNone),
		sec("speedtest", "speedtest", "Diagnostics", "speedtest", "Runs a WAN speed test. Uses bandwidth and can take a minute.", 90*time.Second, true, false, DebugArgNone),
	}
}

func lookupDebugCommand(id string) (DebugCommand, bool) {
	for _, c := range debugCommands() {
		if c.ID == id {
			return c, true
		}
	}
	return DebugCommand{}, false
}

func allowedDaemon(name string) bool {
	for _, d := range debugDaemons {
		if d == name {
			return true
		}
	}
	return false
}

func (c DebugCommand) Build(arg string) (string, error) {
	arg = strings.TrimSpace(arg)
	switch c.Arg {
	case DebugArgNone:
		return c.Command, nil
	case DebugArgHost:
		if arg == "" {
			return "", fmt.Errorf("host is required")
		}
		if !debugHostRe.MatchString(arg) {
			return "", fmt.Errorf("invalid host")
		}
	case DebugArgDaemon:
		if arg == "" {
			return "", fmt.Errorf("daemon is required")
		}
		if !allowedDaemon(arg) {
			return "", fmt.Errorf("unknown daemon")
		}
	case DebugArgPool:
		if arg == "" {
			arg = "1"
		}
		if !debugPoolRe.MatchString(arg) {
			return "", fmt.Errorf("pool must be 1–16")
		}
	}
	if strings.Contains(c.Command, "%s") {
		return strings.Replace(c.Command, "%s", arg, 1), nil
	}
	return c.Command, nil
}

func redactSecretLine(line string) string {
	indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) == 0 {
		return indent + "<redacted>"
	}
	keep := 1
	if len(fields) >= 2 && (fields[0] == "tailscale" || fields[0] == "management" || fields[0] == "radius-server") {
		keep = 2
	}
	if keep > len(fields) {
		keep = len(fields)
	}
	return indent + strings.Join(fields[:keep], " ") + " <redacted>"
}

func SanitizeCLIOutput(raw string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r", ""), "\n") {
		if secretLine(strings.TrimSpace(line)) {
			b.WriteString(redactSecretLine(line))
		} else {
			b.WriteString(line)
		}
		b.WriteByte('\n')
	}
	return strings.TrimRight(b.String(), "\n")
}

type debugRunRequest struct {
	ID  string `json:"id"`
	Arg string `json:"arg"`
}

func (s *Server) handleDebug(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cmds := debugCommands()
		out := make([]map[string]any, 0, len(cmds))
		for _, c := range cmds {
			item := map[string]any{
				"id":      c.ID,
				"label":   c.Label,
				"group":   c.Group,
				"command": strings.Replace(c.Command, "%s", "<arg>", 1),
			}
			if c.Arg != DebugArgNone {
				item["arg"] = string(c.Arg)
			}
			if c.Note != "" {
				item["note"] = c.Note
			}
			if c.Heavy {
				item["heavy"] = true
			}
			if c.Arg == DebugArgDaemon {
				item["choices"] = debugDaemons
			}
			out = append(out, item)
		}
		writeJSON(w, map[string]any{"commands": out})
	case http.MethodPost:
		s.handleDebugRun(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleDebugRun(w http.ResponseWriter, r *http.Request) {
	if !isSameOrigin(r) {
		writeCrossOriginBlocked(w)
		return
	}
	var req debugRunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"detail": "invalid JSON"})
		return
	}
	cmd, ok := lookupDebugCommand(req.ID)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"detail": "unknown command"})
		return
	}
	line, err := cmd.Build(req.Arg)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"detail": err.Error()})
		return
	}
	start := time.Now()
	raw, runErr := s.Client.Run(line, cmd.Timeout)
	out := stripCLI(raw, line)
	if cmd.Sanitize {
		out = SanitizeCLIOutput(out)
	}
	resp := map[string]any{
		"id":      cmd.ID,
		"command": line,
		"output":  out,
		"ms":      time.Since(start).Milliseconds(),
	}
	if runErr != nil {
		resp["detail"] = runErr.Error()
	}
	writeJSON(w, resp)
}
