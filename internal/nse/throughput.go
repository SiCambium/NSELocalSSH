package nse

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	ifconfigNameRE = regexp.MustCompile(`^(\S+):\s+flags=`)
	ifconfigInetRE = regexp.MustCompile(`inet (\d+\.\d+\.\d+\.\d+)\s+netmask\s+(\S+)`)
	ifconfigMACRE  = regexp.MustCompile(`ether ([0-9a-fA-F:]+)`)
	ifconfigRxRE   = regexp.MustCompile(`RX packets\s+(\d+)\s+bytes\s+(\d+)`)
	ifconfigTxRE   = regexp.MustCompile(`TX packets\s+(\d+)\s+bytes\s+(\d+)`)
	ifconfigRxErr  = regexp.MustCompile(`RX errors\s+(\d+)\s+dropped\s+(\d+)`)
	ifconfigTxErr  = regexp.MustCompile(`TX errors\s+(\d+)\s+dropped\s+(\d+)`)
	linuxEthRE     = regexp.MustCompile(`^eth(\d+)$`)
	vlanIfaceRE    = regexp.MustCompile(`^br\d+\.(\d+)$`)
)

type IfconfigIface struct {
	Name      string `json:"name"`
	CLIName   string `json:"cli_name,omitempty"`
	Label     string `json:"label"`
	Kind      string `json:"kind"`
	Role      string `json:"role"`
	VLAN      int    `json:"vlan,omitempty"`
	Flags     string `json:"flags,omitempty"`
	Running   bool   `json:"running"`
	IPv4      string `json:"ipv4,omitempty"`
	Mask      string `json:"mask,omitempty"`
	MAC       string `json:"mac,omitempty"`
	RxPackets int64  `json:"rx_packets"`
	RxBytes   int64  `json:"rx_bytes"`
	TxPackets int64  `json:"tx_packets"`
	TxBytes   int64  `json:"tx_bytes"`
	RxErrors  int64  `json:"rx_errors,omitempty"`
	RxDropped int64  `json:"rx_dropped,omitempty"`
	TxErrors  int64  `json:"tx_errors,omitempty"`
	TxDropped int64  `json:"tx_dropped,omitempty"`
}

type Throughput struct {
	Name      string  `json:"name"`
	CLIName   string  `json:"cli_name,omitempty"`
	Label     string  `json:"label"`
	Kind      string  `json:"kind"`
	Role      string  `json:"role"`
	VLAN      int     `json:"vlan,omitempty"`
	IPv4      string  `json:"ipv4,omitempty"`
	RxBps     float64 `json:"rx_bps"`
	TxBps     float64 `json:"tx_bps"`
	RxBytes   int64   `json:"rx_bytes"`
	TxBytes   int64   `json:"tx_bytes"`
	RxPackets int64   `json:"rx_packets"`
	TxPackets int64   `json:"tx_packets"`
	Running   bool    `json:"running"`
	Active    bool    `json:"active"`
}

func cliEthFromLinux(name string) string {
	m := linuxEthRE.FindStringSubmatch(name)
	if m == nil {
		return ""
	}
	n, _ := strconv.Atoi(m[1])
	return "eth" + strconv.Itoa(n+1)
}

// classifyIface decides whether a physical ethN port is WAN or LAN.
// wanPorts, when non-nil, is ground truth (from cloud-json-config's
// wan_interfaces[].lan_intf) keyed by CLI name ("eth1"); this always wins,
// since a WAN port with no live IP yet (DHCP not up, cable unplugged) must
// still show as WAN, not fall through to LAN. When wanPorts is nil (ground
// truth unavailable), fall back to the old IP-presence heuristic.
func classifyIface(name string, ip string, running bool, wanPorts map[string]bool) (kind, role, label, cli string, vlan int) {
	cli = cliEthFromLinux(name)
	switch {
	case name == "lo":
		return "loopback", "other", "loopback", "", 0
	case linuxEthRE.MatchString(name):
		label = cli
		isWAN := ip != ""
		if wanPorts != nil {
			isWAN = wanPorts[cli]
		}
		if isWAN {
			return "physical", "wan", label + " (WAN)", cli, 0
		}
		if running {
			return "physical", "lan", label + " (LAN)", cli, 0
		}
		return "physical", "unused", label, cli, 0
	case vlanIfaceRE.MatchString(name):
		vlan, _ = strconv.Atoi(vlanIfaceRE.FindStringSubmatch(name)[1])
		label = "vlan" + strconv.Itoa(vlan)
		return "vlan", "vlan", label, "", vlan
	case strings.HasPrefix(name, "br"):
		return "bridge", "other", name, "", 0
	case strings.Contains(name, "tailscale") || name == "ts-host" ||
		strings.HasPrefix(name, "wg") || strings.HasPrefix(name, "tun") ||
		strings.HasPrefix(name, "ppp") || strings.HasPrefix(name, "l2tp") ||
		strings.Contains(name, "ipsec") || strings.HasPrefix(name, "tap"):
		label = name
		if name == "ts-host" || strings.Contains(name, "tailscale") {
			label = "Tailscale"
		}
		return "vpn", "vpn", label, "", 0
	default:
		return "other", "other", name, "", 0
	}
}

func ParseIfconfig(raw string, wanPorts map[string]bool) []IfconfigIface {
	var rows []IfconfigIface
	var cur *IfconfigIface
	flush := func() {
		if cur == nil {
			return
		}
		cur.Kind, cur.Role, cur.Label, cur.CLIName, cur.VLAN = classifyIface(cur.Name, cur.IPv4, cur.Running, wanPorts)
		if cur.CLIName == "" {
			cur.CLIName = cur.Name
		}
		rows = append(rows, *cur)
		cur = nil
	}
	for _, line := range strings.Split(stripCLI(raw, "service show ifconfig"), "\n") {
		if m := ifconfigNameRE.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			flush()
			flags := ""
			if i := strings.Index(line, "flags="); i >= 0 {
				flags = strings.TrimSpace(line[i+6:])
			}
			n := IfconfigIface{Name: m[1], Flags: flags, Running: strings.Contains(flags, "RUNNING")}
			cur = &n
			continue
		}
		if cur == nil {
			continue
		}
		if m := ifconfigInetRE.FindStringSubmatch(line); m != nil {
			cur.IPv4, cur.Mask = m[1], m[2]
		}
		if m := ifconfigMACRE.FindStringSubmatch(line); m != nil {
			cur.MAC = m[1]
		}
		if m := ifconfigRxRE.FindStringSubmatch(line); m != nil {
			cur.RxPackets, _ = strconv.ParseInt(m[1], 10, 64)
			cur.RxBytes, _ = strconv.ParseInt(m[2], 10, 64)
		}
		if m := ifconfigTxRE.FindStringSubmatch(line); m != nil {
			cur.TxPackets, _ = strconv.ParseInt(m[1], 10, 64)
			cur.TxBytes, _ = strconv.ParseInt(m[2], 10, 64)
		}
		if m := ifconfigRxErr.FindStringSubmatch(line); m != nil {
			cur.RxErrors, _ = strconv.ParseInt(m[1], 10, 64)
			cur.RxDropped, _ = strconv.ParseInt(m[2], 10, 64)
		}
		if m := ifconfigTxErr.FindStringSubmatch(line); m != nil {
			cur.TxErrors, _ = strconv.ParseInt(m[1], 10, 64)
			cur.TxDropped, _ = strconv.ParseInt(m[2], 10, 64)
		}
	}
	flush()
	return rows
}

func bpsFromDelta(prev, cur int64, seconds float64) float64 {
	if seconds <= 0 || cur < prev {
		return 0
	}
	return float64(cur-prev) * 8 / seconds
}

func RatesFromSamples(prev, cur []IfconfigIface, dt time.Duration) []Throughput {
	seconds := dt.Seconds()
	index := map[string]IfconfigIface{}
	for _, p := range prev {
		index[p.Name] = p
	}
	var out []Throughput
	for _, c := range cur {
		row := Throughput{
			Name: c.Name, CLIName: c.CLIName, Label: c.Label, Kind: c.Kind, Role: c.Role,
			VLAN: c.VLAN, IPv4: c.IPv4, RxBytes: c.RxBytes, TxBytes: c.TxBytes,
			RxPackets: c.RxPackets, TxPackets: c.TxPackets, Running: c.Running,
		}
		if p, ok := index[c.Name]; ok {
			row.RxBps = bpsFromDelta(p.RxBytes, c.RxBytes, seconds)
			row.TxBps = bpsFromDelta(p.TxBytes, c.TxBytes, seconds)
		}
		row.Active = row.RxBps > 0 || row.TxBps > 0
		out = append(out, row)
	}
	return out
}
