package nse

import (
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var promptRE = regexp.MustCompile(`(?m)^[A-Za-z0-9._-]+\([^)]*\)#\s*$`)
var eventRE = regexp.MustCompile(`^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)$`)
var appStatRE = regexp.MustCompile(`^(.+?)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$`)

func stripCLI(raw, command string) string {
	text := strings.ReplaceAll(raw, "\r", "")
	if command != "" {
		trimmed := strings.TrimLeft(text, "\n")
		if strings.HasPrefix(strings.TrimSpace(trimmed), command) {
			// drop the echoed command line
			if i := strings.Index(trimmed, "\n"); i >= 0 {
				text = trimmed[i+1:]
			} else {
				text = ""
			}
		}
	}
	text = promptRE.ReplaceAllString(text, "")
	return strings.Trim(text, "\n")
}

func linesOf(raw, command string) []string {
	body := stripCLI(raw, command)
	if body == "" {
		return nil
	}
	out := strings.Split(body, "\n")
	for i, ln := range out {
		out[i] = strings.TrimRight(ln, " \t")
	}
	return out
}

func lastField(line string) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
}

type Version struct {
	Identity         string `json:"identity,omitempty"`
	Hostname         string `json:"hostname,omitempty"`
	Model            string `json:"model,omitempty"`
	RegulatoryDomain string `json:"regulatory_domain,omitempty"`
	SoftwareVersion  string `json:"software_version,omitempty"`
	BuildDate        string `json:"build_date,omitempty"`
	DeviceAgent      string `json:"device_agent,omitempty"`
	Serial           string `json:"serial,omitempty"`
	Uptime           string `json:"uptime,omitempty"`
	MAC              string `json:"mac,omitempty"`
}

func ParseVersion(raw string) Version {
	body := stripCLI(raw, "show version")
	var out Version
	parts := strings.SplitN(body, "\n", 2)
	first := strings.TrimSpace(parts[0])
	if first != "" {
		out.Identity = first
		if i := strings.Index(first, " "); i >= 0 {
			out.Hostname = first[:i]
			out.Model = first[i+1:]
		}
	}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Regulatory domain"):
			out.RegulatoryDomain = lastField(line)
		case strings.HasPrefix(line, "Software version"):
			out.SoftwareVersion = lastField(line)
		case strings.HasPrefix(line, "Build date"):
			out.BuildDate = lastField(line)
		case strings.HasPrefix(line, "Device-Agent version"):
			out.DeviceAgent = lastField(line)
		case strings.HasPrefix(line, "Serial number"):
			out.Serial = lastField(line)
		case strings.HasPrefix(line, "System is up"):
			out.Uptime = strings.TrimSpace(strings.TrimPrefix(line, "System is up"))
		case strings.Contains(line, "MAC address"):
			out.MAC = lastField(line)
		}
	}
	return out
}

type Clock struct {
	Clock string `json:"clock"`
}

func ParseClock(raw string) Clock {
	return Clock{Clock: strings.TrimSpace(stripCLI(raw, "show clock"))}
}

type Conntrack struct {
	Limit int    `json:"limit"`
	Usage int    `json:"usage"`
	Flows int    `json:"flows"`
	NAT   int    `json:"nat"`
	Raw   string `json:"raw,omitempty"`
}

var conntrackFlowRe = regexp.MustCompile(`(\d+)\s+flow entries`)

func ParseConntrack(raw string) Conntrack {
	body := stripCLI(raw, "service show conntrack")
	out := Conntrack{Raw: body}
	for _, line := range strings.Split(body, "\n") {
		s := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(s, "Total Conntrack Limit:"):
			out.Limit, _ = strconv.Atoi(lastField(s))
		case strings.HasPrefix(s, "Total Conntrack Usage:"):
			out.Usage, _ = strconv.Atoi(lastField(s))
		case strings.HasPrefix(s, "Total NAT Usage:"):
			out.NAT, _ = strconv.Atoi(lastField(s))
		}
		if m := conntrackFlowRe.FindStringSubmatch(s); len(m) == 2 {
			out.Flows, _ = strconv.Atoi(m[1])
		}
	}
	return out
}

type Management struct {
	Remote map[string]string `json:"remote"`
	GUI    map[string]string `json:"gui"`
	CLI    map[string]string `json:"cli"`
}

func ParseManagement(raw string) Management {
	m := Management{
		Remote: map[string]string{},
		GUI:    map[string]string{},
		CLI:    map[string]string{},
	}
	section := ""
	for _, line := range strings.Split(stripCLI(raw, "show management"), "\n") {
		stripped := strings.TrimSpace(line)
		switch stripped {
		case "Remote Management":
			section = "remote"
			continue
		case "GUI":
			section = "gui"
			continue
		case "Command Line":
			section = "cli"
			continue
		}
		key, val, ok := strings.Cut(stripped, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(key), "-", "_"), " ", "_"))
		val = strings.TrimSpace(val)
		switch section {
		case "remote":
			m.Remote[key] = val
		case "gui":
			m.GUI[key] = val
		case "cli":
			m.CLI[key] = val
		}
	}
	return m
}

func ParseCambium(raw string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(stripCLI(raw, "show cambium"), "\n") {
		if key, val, ok := strings.Cut(line, ":"); ok {
			k := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(key), "-", "_"))
			out[k] = strings.TrimSpace(val)
		}
	}
	return out
}

type RemoteInfo struct {
	Summary map[string]string `json:"summary"`
	Raw     string            `json:"raw"`
}

func ParseRemote(raw string) RemoteInfo {
	body := stripCLI(raw, "show remote")
	status := map[string]string{}
	for _, line := range strings.Split(body, "\n") {
		switch {
		case strings.HasPrefix(line, "Device Status:"):
			status["device_status"] = strings.TrimSpace(strings.TrimPrefix(line, "Device Status:"))
		case strings.HasPrefix(line, "State:"):
			status["state"] = strings.TrimSpace(strings.TrimPrefix(line, "State:"))
		case strings.HasPrefix(line, "Last disconnection reason:"):
			status["last_disconnect"] = strings.TrimSpace(strings.TrimPrefix(line, "Last disconnection reason:"))
		}
	}
	return RemoteInfo{Summary: status, Raw: body}
}

type Interface struct {
	Interface   string `json:"interface"`
	MAC         string `json:"mac"`
	Status      string `json:"status"`
	Speed       string `json:"speed"`
	Duplex      string `json:"duplex"`
	Advertising string `json:"advertising"`
}

func ParseInterfaceBrief(raw string) []Interface {
	var rows []Interface
	for _, line := range linesOf(raw, "show interface brief") {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "INTERFACE") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		row := Interface{Interface: parts[0], MAC: parts[1], Status: parts[2]}
		if len(parts) > 3 {
			row.Speed = parts[3]
		}
		if len(parts) > 4 {
			row.Duplex = parts[4]
		}
		if len(parts) > 5 {
			row.Advertising = parts[5]
		}
		rows = append(rows, row)
	}
	return rows
}

type ARPEntry struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac"`
	Flags    string `json:"flags"`
	Iface    string `json:"iface"`
	Complete bool   `json:"complete"`
}

func ParseARP(raw string) []ARPEntry {
	var rows []ARPEntry
	inIP := false
	for _, line := range linesOf(raw, "show arp") {
		if strings.HasPrefix(line, "IP_ADDR") {
			inIP = true
			continue
		}
		if strings.HasPrefix(line, "PORTID") || strings.HasPrefix(line, "br") || strings.Contains(line, "bridge ARP") {
			inIP = false
			continue
		}
		if !inIP || strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 5 && parts[1] == "ether" {
			rows = append(rows, ARPEntry{IP: parts[0], MAC: parts[2], Flags: parts[3], Iface: parts[4], Complete: true})
		} else if len(parts) >= 4 && parts[1] == "(incomplete)" {
			rows = append(rows, ARPEntry{IP: parts[0], Flags: parts[2], Iface: parts[3], Complete: false})
		}
	}
	return rows
}

type Route struct {
	Destination string `json:"destination"`
	Mask        string `json:"mask"`
	Gateway     string `json:"gateway"`
	Flags       string `json:"flags"`
	Metric      string `json:"metric"`
	Interface   string `json:"interface"`
}

func ParseRoute(raw string) []Route {
	first := strings.TrimSpace(strings.SplitN(strings.ReplaceAll(raw, "\r", ""), "\n", 2)[0])
	cmd := "show route"
	if strings.HasPrefix(first, "show") {
		cmd = first
	}
	var rows []Route
	for _, line := range linesOf(raw, cmd) {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "DESTINATION") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 6 {
			continue
		}
		rows = append(rows, Route{
			Destination: parts[0], Mask: parts[1], Gateway: parts[2],
			Flags: parts[3], Metric: parts[4], Interface: parts[5],
		})
	}
	return rows
}

type Lease struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	Expires  string `json:"expires"`
}

type DHCPPool struct {
	Pool      int     `json:"pool"`
	Status    string  `json:"status,omitempty"`
	Interface string  `json:"interface,omitempty"`
	Allocated string  `json:"allocated,omitempty"`
	Usage     string  `json:"usage,omitempty"`
	Leases    []Lease `json:"leases"`
}

func ParseDHCPPool(raw string, poolID int) (DHCPPool, bool) {
	cmd := "show dhcp-pool " + strconv.Itoa(poolID)
	body := stripCLI(raw, cmd)
	if body == "" || strings.Contains(body, "Specify arguments") || strings.Contains(body, "Error") {
		return DHCPPool{}, false
	}
	info := DHCPPool{Pool: poolID, Leases: []Lease{}}
	inLeases := false
	for _, line := range strings.Split(body, "\n") {
		stripped := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(stripped, "Pool Status:"):
			info.Status = strings.TrimSpace(strings.TrimPrefix(stripped, "Pool Status:"))
		case strings.HasPrefix(stripped, "Pool Interface:"):
			info.Interface = strings.TrimSpace(strings.TrimPrefix(stripped, "Pool Interface:"))
		case strings.HasPrefix(stripped, "Allocated leases:"):
			info.Allocated = strings.TrimSpace(strings.TrimPrefix(stripped, "Allocated leases:"))
		case strings.HasPrefix(stripped, "Pool usage:"):
			info.Usage = strings.TrimSpace(strings.TrimPrefix(stripped, "Pool usage:"))
		case strings.HasPrefix(stripped, "MAC"):
			inLeases = true
		case inLeases && stripped != "":
			parts := strings.Fields(stripped)
			if len(parts) >= 4 {
				info.Leases = append(info.Leases, Lease{
					MAC: parts[0], IP: parts[1], Hostname: parts[2], Expires: strings.Join(parts[3:], " "),
				})
			}
		}
	}
	if info.Status == "" && len(info.Leases) == 0 {
		return DHCPPool{}, false
	}
	return info, true
}

type IPDHCP struct {
	Interface string            `json:"interface"`
	Options   map[string]string `json:"options"`
}

func ParseIPDHCP(raw string) []IPDHCP {
	var blocks []IPDHCP
	var current *IPDHCP
	for _, line := range strings.Split(stripCLI(raw, "show ip dhcp"), "\n") {
		stripped := strings.TrimSpace(line)
		if strings.HasPrefix(stripped, "Interface Name") {
			if current != nil {
				blocks = append(blocks, *current)
			}
			iface := strings.TrimSpace(stripped[strings.Index(stripped, ":")+1:])
			current = &IPDHCP{Interface: iface, Options: map[string]string{}}
			continue
		}
		if current != nil {
			if k, v, ok := strings.Cut(stripped, "="); ok {
				current.Options[k] = v
			}
		}
	}
	if current != nil {
		blocks = append(blocks, *current)
	}
	return blocks
}

type Event struct {
	Time    string `json:"time"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func ParseEvents(raw string) []Event {
	var rows []Event
	for _, line := range strings.Split(stripCLI(raw, "show events"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if m := eventRE.FindStringSubmatch(line); m != nil {
			rows = append(rows, Event{Time: m[1], Code: m[2], Message: m[3]})
		} else {
			rows = append(rows, Event{Message: line})
		}
	}
	return rows
}

type LLDPNeighbor struct {
	Header    string            `json:"header"`
	Interface string            `json:"interface"`
	SysName   string            `json:"sysname,omitempty"`
	SysDescr  string            `json:"sysdescr,omitempty"`
	MgmtIP    string            `json:"mgmt_ip,omitempty"`
	Fields    map[string]string `json:"fields"`
}

func ParseLLDPNeighbors(raw string) []LLDPNeighbor {
	var neighbors []LLDPNeighbor
	var current *LLDPNeighbor
	flush := func() {
		if current != nil {
			neighbors = append(neighbors, *current)
		}
	}
	for _, line := range strings.Split(stripCLI(raw, "show lldp neighbors"), "\n") {
		if strings.HasPrefix(line, "Interface:") {
			flush()
			n := LLDPNeighbor{Header: strings.TrimSpace(line), Fields: map[string]string{}}
			rest := strings.TrimSpace(strings.TrimPrefix(line, "Interface:"))
			n.Interface, _, _ = strings.Cut(rest, ",")
			n.Interface = strings.TrimSpace(n.Interface)
			current = &n
			continue
		}
		if current == nil {
			continue
		}
		if key, val, ok := strings.Cut(line, ":"); ok {
			key, val = strings.TrimSpace(key), strings.TrimSpace(val)
			if key == "" {
				continue
			}
			current.Fields[key] = val
			switch key {
			case "SysName":
				current.SysName = val
			case "SysDescr":
				current.SysDescr = val
			case "MgmtIP":
				if current.MgmtIP == "" {
					current.MgmtIP = val
				}
			}
		}
	}
	flush()
	return neighbors
}

type PPPoE struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	VLAN    string `json:"vlan"`
	Address string `json:"address"`
	Uptime  string `json:"uptime"`
}

func ParsePPPoE(raw string) []PPPoE {
	var rows []PPPoE
	for _, line := range linesOf(raw, "show pppoe") {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "TYPE") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 4 {
			row := PPPoE{Type: parts[0], Status: parts[1], VLAN: parts[2], Address: parts[3]}
			if len(parts) > 4 {
				row.Uptime = parts[4]
			}
			rows = append(rows, row)
		}
	}
	return rows
}

type USB struct {
	USB string `json:"usb"`
}

func ParseUSB(raw string) USB {
	return USB{USB: stripCLI(raw, "show usb")}
}

func ParsePower(raw string) map[string]string {
	out := map[string]string{}
	for _, line := range linesOf(raw, "show power") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}

type MemoryField struct {
	Key   string `json:"key"`
	KB    int64  `json:"kb,omitempty"`
	Extra string `json:"extra,omitempty"`
	Raw   string `json:"raw"`
}

type Memory struct {
	TotalKB     int64         `json:"total_kb,omitempty"`
	UsedKB      int64         `json:"used_kb,omitempty"`
	FreeKB      int64         `json:"free_kb,omitempty"`
	SharedKB    int64         `json:"shared_kb,omitempty"`
	CacheKB     int64         `json:"cache_kb,omitempty"`
	AvailableKB int64         `json:"available_kb,omitempty"`
	SwapTotalKB int64         `json:"swap_total_kb,omitempty"`
	SwapUsedKB  int64         `json:"swap_used_kb,omitempty"`
	MemTotalKB  int64         `json:"memtotal_kb,omitempty"`
	MemAvailKB  int64         `json:"memavailable_kb,omitempty"`
	UsedPct     float64       `json:"used_pct,omitempty"`
	Rows        []MemoryField `json:"rows,omitempty"`
}

func ParseMemory(raw string) Memory {
	var out Memory
	out.Rows = []MemoryField{}
	for _, line := range strings.Split(stripCLI(raw, "service show memory"), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		switch {
		case strings.HasPrefix(trimmed, "Mem:"):
			parts := strings.Fields(trimmed)
			if len(parts) >= 7 {
				out.TotalKB, _ = strconv.ParseInt(parts[1], 10, 64)
				out.UsedKB, _ = strconv.ParseInt(parts[2], 10, 64)
				out.FreeKB, _ = strconv.ParseInt(parts[3], 10, 64)
				out.SharedKB, _ = strconv.ParseInt(parts[4], 10, 64)
				out.CacheKB, _ = strconv.ParseInt(parts[5], 10, 64)
				out.AvailableKB, _ = strconv.ParseInt(parts[6], 10, 64)
			}
			out.Rows = append(out.Rows, MemoryField{Key: "Mem", Raw: trimmed})
		case strings.HasPrefix(trimmed, "Swap:"):
			parts := strings.Fields(trimmed)
			if len(parts) >= 3 {
				out.SwapTotalKB, _ = strconv.ParseInt(parts[1], 10, 64)
				out.SwapUsedKB, _ = strconv.ParseInt(parts[2], 10, 64)
			}
			out.Rows = append(out.Rows, MemoryField{Key: "Swap", Raw: trimmed})
		default:
			key, rest, ok := strings.Cut(trimmed, ":")
			if !ok {
				continue
			}
			fields := strings.Fields(strings.TrimSpace(rest))
			row := MemoryField{Key: strings.TrimSpace(key), Raw: trimmed}
			if len(fields) >= 1 {
				row.KB, _ = strconv.ParseInt(fields[0], 10, 64)
			}
			if len(fields) >= 2 {
				row.Extra = strings.Join(fields[1:], " ")
			}
			out.Rows = append(out.Rows, row)
			switch row.Key {
			case "MemTotal":
				out.MemTotalKB = row.KB
			case "MemAvailable":
				out.MemAvailKB = row.KB
			}
		}
	}
	if out.TotalKB > 0 {
		out.UsedPct = math.Round(1000*float64(out.UsedKB)/float64(out.TotalKB)) / 10
	}
	return out
}

type Disk struct {
	Filesystem string `json:"filesystem"`
	Blocks     string `json:"blocks"`
	Used       string `json:"used"`
	Available  string `json:"available"`
	UsePct     string `json:"use_pct"`
	Mounted    string `json:"mounted"`
}

func ParseDF(raw string) []Disk {
	cmd := "service show flash"
	if strings.Contains(raw[:min(40, len(raw))], "service show df") {
		cmd = "service show df"
	}
	var rows []Disk
	started := false
	for _, line := range linesOf(raw, cmd) {
		if strings.HasPrefix(line, "Filesystem") {
			started = true
			continue
		}
		if !started || strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 6 {
			rows = append(rows, Disk{
				Filesystem: parts[0], Blocks: parts[1], Used: parts[2],
				Available: parts[3], UsePct: parts[4], Mounted: parts[5],
			})
		}
	}
	return rows
}

type FilterCounter struct {
	Name       string `json:"name"`
	Precedence string `json:"precedence"`
	Type       string `json:"type"`
	Layer      string `json:"layer"`
	State      string `json:"state"`
	Packets    string `json:"packets"`
	Bytes      string `json:"bytes"`
}

func ParseFilterCounters(raw string) []FilterCounter {
	cmd := "show filter"
	if strings.Contains(raw[:min(80, len(raw))], "global-filter") {
		cmd = "show filter global-filter"
	}
	var rows []FilterCounter
	for _, line := range linesOf(raw, cmd) {
		s := strings.TrimSpace(line)
		if s == "" || (strings.Contains(line, "Name") && strings.Contains(line, "Precedence")) {
			continue
		}
		if strings.Trim(s, "- ") == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 6 {
			row := FilterCounter{
				Name: parts[0], Precedence: parts[1], Type: parts[2],
				Layer: parts[3], State: parts[4], Packets: parts[5],
			}
			if len(parts) > 6 {
				row.Bytes = parts[6]
			}
			rows = append(rows, row)
		}
	}
	return rows
}

type AppStat struct {
	Name      string `json:"name"`
	TxPackets int64  `json:"tx_packets"`
	TxBytes   int64  `json:"tx_bytes"`
	RxPackets int64  `json:"rx_packets"`
	RxBytes   int64  `json:"rx_bytes"`
}

func ParseAppStats(raw string) []AppStat {
	var rows []AppStat
	for _, line := range strings.Split(stripCLI(raw, ""), "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "-") || strings.HasPrefix(line, "=") {
			continue
		}
		if strings.Contains(line, "Packets") || (strings.Contains(line, "Application") && !strings.Contains(line, "Count")) {
			continue
		}
		if strings.HasPrefix(line, "Applications Count") {
			continue
		}
		m := appStatRE.FindStringSubmatch(strings.TrimRight(line, " \t"))
		if m == nil {
			continue
		}
		name := strings.TrimSpace(m[1])
		if strings.HasPrefix(strings.ToLower(name), "protocol") {
			continue
		}
		txp, _ := strconv.ParseInt(m[2], 10, 64)
		txb, _ := strconv.ParseInt(m[3], 10, 64)
		rxp, _ := strconv.ParseInt(m[4], 10, 64)
		rxb, _ := strconv.ParseInt(m[5], 10, 64)
		rows = append(rows, AppStat{Name: name, TxPackets: txp, TxBytes: txb, RxPackets: rxp, RxBytes: rxb})
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].TxBytes+rows[i].RxBytes > rows[j].TxBytes+rows[j].RxBytes
	})
	return rows
}

type FilterRule struct {
	ID         string `json:"id,omitempty"`
	Name       string `json:"name,omitempty"`
	Precedence string `json:"precedence,omitempty"`
	Rule       string `json:"rule,omitempty"`
}

func ParseConfigFilter(raw string) []FilterRule {
	var rows []FilterRule
	current := FilterRule{}
	has := false
	flush := func() {
		if has {
			rows = append(rows, current)
			current = FilterRule{}
			has = false
		}
	}
	for _, line := range strings.Split(stripCLI(raw, "show config filter"), "\n") {
		stripped := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(stripped, "filter precedence"):
			flush()
			fields := strings.Fields(stripped)
			current.Precedence = fields[len(fields)-1]
			has = true
		case strings.HasPrefix(stripped, "unique_id"):
			current.ID = lastField(stripped)
			has = true
		case strings.HasPrefix(stripped, "rule-name"):
			current.Name = strings.TrimSpace(strings.TrimPrefix(stripped, "rule-name"))
			has = true
		case strings.HasPrefix(stripped, "layer3-filter"):
			current.Rule = strings.TrimSpace(strings.TrimPrefix(stripped, "layer3-filter"))
			has = true
		case stripped == "exit" && has:
			flush()
		}
	}
	flush()
	return rows
}

type TailscalePeer struct {
	IP      string `json:"ip"`
	Name    string `json:"name"`
	User    string `json:"user"`
	OS      string `json:"os"`
	Status  string `json:"status"`
	Offline bool   `json:"offline"`
	Idle    bool   `json:"idle"`
	Exit    bool   `json:"exit_node"`
	Self    bool   `json:"self"`
}

var tailscalePeerRE = regexp.MustCompile(`^(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$`)

func ParseTailscaleStatus(raw string) []TailscalePeer {
	var peers []TailscalePeer
	for _, line := range linesOf(raw, "show tailscale status") {
		m := tailscalePeerRE.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		status := strings.TrimSpace(m[5])
		if status == "-" {
			status = "online"
		}
		low := strings.ToLower(status)
		p := TailscalePeer{
			IP:      m[1],
			Name:    m[2],
			User:    m[3],
			OS:      m[4],
			Status:  status,
			Offline: strings.Contains(low, "offline"),
			Idle:    strings.Contains(low, "idle"),
			Exit:    strings.Contains(low, "exit node"),
		}
		peers = append(peers, p)
	}
	if len(peers) > 0 {
		peers[0].Self = true
	}
	return peers
}

type VPNSessions struct {
	Kind      string              `json:"kind"`
	EmptyJSON bool                `json:"empty_json"`
	Error     string              `json:"error,omitempty"`
	Rows      []map[string]string `json:"rows"`
}

func ParseVPNSessions(raw string) VPNSessions {
	body := stripCLI(raw, "")
	out := VPNSessions{Rows: []map[string]string{}}
	low := strings.ToLower(body)
	if strings.Contains(low, "unable to process json") {
		out.EmptyJSON = true
		for _, line := range strings.Split(body, "\n") {
			if strings.Contains(strings.ToLower(line), "unable to process json") {
				out.Error = strings.TrimSpace(line)
				break
			}
		}
		return out
	}
	if strings.Contains(low, "%error") {
		out.Error = strings.TrimSpace(body)
		return out
	}
	return out
}

type PingResult struct {
	OK          bool   `json:"ok"`
	Target      string `json:"target,omitempty"`
	Transmitted int    `json:"transmitted"`
	Received    int    `json:"received"`
	LossPct     string `json:"loss_pct,omitempty"`
	RTT         string `json:"rtt,omitempty"`
}

var pingStatRE = regexp.MustCompile(`(\d+) packets transmitted, (\d+) packets received, ([0-9.]+%) packet loss`)
var pingRTTRE = regexp.MustCompile(`round-trip min/avg/max = ([0-9./ ]+ ms)`)
var pingTargetRE = regexp.MustCompile(`PING ([0-9.]+)`)

func ParsePing(raw string) PingResult {
	body := stripCLI(raw, "")
	var out PingResult
	if m := pingTargetRE.FindStringSubmatch(body); m != nil {
		out.Target = m[1]
	}
	if m := pingStatRE.FindStringSubmatch(body); m != nil {
		out.Transmitted, _ = strconv.Atoi(m[1])
		out.Received, _ = strconv.Atoi(m[2])
		out.LossPct = m[3]
		out.OK = out.Received > 0
	}
	if m := pingRTTRE.FindStringSubmatch(body); m != nil {
		out.RTT = strings.TrimSpace(m[1])
	}
	return out
}

type StarlinkConfig struct {
	Enabled   bool   `json:"enabled"`
	WANName   string `json:"wan_name,omitempty"`
	Interface string `json:"interface,omitempty"`
	DishMode  string `json:"dish_mode,omitempty"`
	DishIP    string `json:"dish_ip,omitempty"`
	DishPort  string `json:"dish_port,omitempty"`
	GRPCIP    string `json:"grpc_ip,omitempty"`
	GRPCPort  string `json:"grpc_port,omitempty"`
}

type VPNServerConfig struct {
	Enabled      bool   `json:"enabled"`
	Interface    string `json:"interface,omitempty"`
	AddressRange string `json:"address_range,omitempty"`
	MFA          bool   `json:"mfa"`
}

type TailscaleConfig struct {
	Enabled         bool   `json:"enabled"`
	AcceptRoutes    bool   `json:"accept_routes"`
	AdvertiseRoutes string `json:"advertise_routes,omitempty"`
	AuthKeySet      bool   `json:"auth_key_set"`
}

type TunnelConfig struct {
	Starlink  StarlinkConfig  `json:"starlink"`
	VPNServer VPNServerConfig `json:"vpn_server"`
	Tailscale TailscaleConfig `json:"tailscale"`
}

func secretLine(s string) bool {
	low := strings.ToLower(s)
	return strings.Contains(low, "shared-secret") ||
		strings.Contains(low, "auth-key") ||
		strings.Contains(low, "password") ||
		strings.Contains(low, "oinkcode") ||
		strings.Contains(low, "psk") ||
		strings.Contains(low, "$crypt$")
}

func ParseTunnelConfig(raw string) TunnelConfig {
	var out TunnelConfig
	currentIface := ""
	currentWAN := ""
	inVPN := false
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r", ""), "\n") {
		stripped := strings.TrimSpace(line)
		if secretLine(stripped) {
			if strings.HasPrefix(stripped, "tailscale auth-key") {
				out.Tailscale.AuthKeySet = true
				out.Tailscale.Enabled = true
			}
			if inVPN && strings.Contains(stripped, "shared-secret") {
				out.VPNServer.Enabled = true
			}
			continue
		}
		if strings.HasPrefix(stripped, "interface eth") {
			currentIface = strings.TrimSpace(strings.TrimPrefix(stripped, "interface "))
			currentWAN = ""
			inVPN = false
			continue
		}
		if strings.HasPrefix(stripped, "wan-name ") {
			currentWAN = strings.TrimSpace(strings.TrimPrefix(stripped, "wan-name "))
			continue
		}
		if stripped == "starlink" || strings.HasPrefix(stripped, "starlink ") {
			out.Starlink.Enabled = true
			out.Starlink.Interface = currentIface
			out.Starlink.WANName = currentWAN
			switch {
			case strings.HasPrefix(stripped, "starlink dish-mode "):
				out.Starlink.DishMode = strings.TrimPrefix(stripped, "starlink dish-mode ")
			case strings.HasPrefix(stripped, "starlink dish-ip "):
				out.Starlink.DishIP = strings.TrimPrefix(stripped, "starlink dish-ip ")
			case strings.HasPrefix(stripped, "starlink dish-port "):
				out.Starlink.DishPort = strings.TrimPrefix(stripped, "starlink dish-port ")
			case strings.HasPrefix(stripped, "starlink dish-grpc-reflection-ip "):
				out.Starlink.GRPCIP = strings.TrimPrefix(stripped, "starlink dish-grpc-reflection-ip ")
			case strings.HasPrefix(stripped, "starlink dish-grpc-reflection-port "):
				out.Starlink.GRPCPort = strings.TrimPrefix(stripped, "starlink dish-grpc-reflection-port ")
			}
			continue
		}
		if stripped == "vpn-server" {
			inVPN = true
			out.VPNServer.Enabled = true
			continue
		}
		if inVPN {
			if stripped == "exit" || stripped == "!" {
				inVPN = false
				continue
			}
			if strings.HasPrefix(stripped, "interface ") {
				out.VPNServer.Interface = strings.TrimPrefix(stripped, "interface ")
			}
			if strings.HasPrefix(stripped, "address-range ") {
				out.VPNServer.AddressRange = strings.TrimPrefix(stripped, "address-range ")
			}
			if stripped == "mfa" {
				out.VPNServer.MFA = true
			}
			continue
		}
		if stripped == "tailscale" || strings.HasPrefix(stripped, "tailscale ") {
			out.Tailscale.Enabled = true
			if stripped == "tailscale accept-routes" {
				out.Tailscale.AcceptRoutes = true
			}
			if strings.HasPrefix(stripped, "tailscale advertise-routes ") {
				out.Tailscale.AdvertiseRoutes = strings.TrimPrefix(stripped, "tailscale advertise-routes ")
			}
		}
	}
	return out
}

var macRe = regexp.MustCompile(`(?i)^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)

type VLAN struct {
	ID               int    `json:"id"`
	Name             string `json:"name"`
	Address          string `json:"address,omitempty"`
	Mask             string `json:"mask,omitempty"`
	ManagementAccess string `json:"management_access,omitempty"`
}

type PortVLAN struct {
	Interface    string `json:"interface"`
	Type         string `json:"type,omitempty"`
	Mode         string `json:"mode,omitempty"`
	AccessVLAN   string `json:"access_vlan,omitempty"`
	NativeVLAN   string `json:"native_vlan,omitempty"`
	AllowedVLANs string `json:"allowed_vlans,omitempty"`
}

type MACBinding struct {
	Pool        int    `json:"pool"`
	MAC         string `json:"mac"`
	IP          string `json:"ip"`
	Description string `json:"description,omitempty"`
}

type DHCPPoolSettings struct {
	Pool         int          `json:"pool"`
	AddressRange string       `json:"address_range,omitempty"`
	Network      string       `json:"network,omitempty"`
	Router       string       `json:"router,omitempty"`
	DNS          string       `json:"dns,omitempty"`
	Lease        string       `json:"lease,omitempty"`
	Domain       string       `json:"domain,omitempty"`
	Bindings     []MACBinding `json:"bindings"`
}

type LANConfig struct {
	VLANs         []VLAN             `json:"vlans"`
	Ports         []PortVLAN         `json:"ports"`
	DHCPPools     []DHCPPoolSettings `json:"dhcp_pools"`
	Bindings      []MACBinding       `json:"bindings"`
	Authoritative bool               `json:"authoritative"`
}

func formatLease(raw string) string {
	parts := strings.Fields(raw)
	if len(parts) == 3 {
		return parts[0] + "d " + parts[1] + "h " + parts[2] + "m"
	}
	return raw
}

func parseBindLine(line string, pool int) (MACBinding, bool) {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return MACBinding{}, false
	}
	cmd := strings.ToLower(fields[0])
	var mac, ip string
	restStart := 3
	switch cmd {
	case "bind", "mac-binding", "bind-list":
		mac, ip = fields[1], fields[2]
	case "hardware-address":
		mac, ip = fields[1], fields[2]
	case "reserved-address":
		ip, mac = fields[1], fields[2]
	default:
		return MACBinding{}, false
	}
	if !macRe.MatchString(mac) {
		return MACBinding{}, false
	}
	desc := ""
	if restStart < len(fields) {
		desc = strings.Join(fields[restStart:], " ")
	}
	return MACBinding{Pool: pool, MAC: strings.ToLower(mac), IP: ip, Description: desc}, true
}

func ParseLANConfig(raw string) LANConfig {
	out := LANConfig{
		VLANs:     []VLAN{},
		Ports:     []PortVLAN{},
		DHCPPools: []DHCPPoolSettings{},
		Bindings:  []MACBinding{},
	}
	block := ""
	var vlan VLAN
	var port PortVLAN
	var pool DHCPPoolSettings
	flushVLAN := func() {
		if vlan.ID != 0 {
			out.VLANs = append(out.VLANs, vlan)
		}
		vlan = VLAN{}
	}
	flushPort := func() {
		if port.Interface != "" {
			out.Ports = append(out.Ports, port)
		}
		port = PortVLAN{}
	}
	flushPool := func() {
		if pool.Pool != 0 {
			if pool.Bindings == nil {
				pool.Bindings = []MACBinding{}
			}
			out.DHCPPools = append(out.DHCPPools, pool)
			out.Bindings = append(out.Bindings, pool.Bindings...)
		}
		pool = DHCPPoolSettings{}
	}
	flush := func() {
		switch block {
		case "vlan":
			flushVLAN()
		case "eth":
			flushPort()
		case "dhcp":
			flushPool()
		}
		block = ""
	}

	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r", ""), "\n") {
		stripped := strings.TrimSpace(line)
		if stripped == "" || secretLine(stripped) {
			continue
		}
		if stripped == "ip dhcp server authoritative" {
			out.Authoritative = true
			continue
		}
		if strings.HasPrefix(stripped, "interface vlan ") {
			flush()
			block = "vlan"
			id, _ := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(stripped, "interface vlan ")))
			vlan = VLAN{ID: id, Name: "vlan" + strconv.Itoa(id)}
			continue
		}
		if strings.HasPrefix(stripped, "interface eth ") || strings.HasPrefix(stripped, "interface eth") {
			flush()
			name := strings.TrimSpace(strings.TrimPrefix(stripped, "interface "))
			name = strings.ReplaceAll(name, " ", "")
			block = "eth"
			port = PortVLAN{Interface: name}
			continue
		}
		if strings.HasPrefix(stripped, "ip dhcp pool ") {
			flush()
			block = "dhcp"
			id, _ := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(stripped, "ip dhcp pool ")))
			pool = DHCPPoolSettings{Pool: id, Bindings: []MACBinding{}}
			continue
		}
		if stripped == "exit" || stripped == "!" {
			flush()
			continue
		}
		switch block {
		case "vlan":
			if strings.HasPrefix(stripped, "ip address ") {
				parts := strings.Fields(strings.TrimPrefix(stripped, "ip address "))
				if len(parts) >= 1 {
					vlan.Address = parts[0]
				}
				if len(parts) >= 2 {
					vlan.Mask = parts[1]
				}
			}
			if strings.HasPrefix(stripped, "management-access ") {
				vlan.ManagementAccess = strings.TrimPrefix(stripped, "management-access ")
			}
		case "eth":
			if strings.HasPrefix(stripped, "type ") {
				port.Type = strings.TrimPrefix(stripped, "type ")
			}
			if strings.HasPrefix(stripped, "switchport mode ") {
				port.Mode = strings.TrimPrefix(stripped, "switchport mode ")
			}
			if strings.HasPrefix(stripped, "switchport access vlan ") {
				port.AccessVLAN = strings.TrimPrefix(stripped, "switchport access vlan ")
			}
			if strings.HasPrefix(stripped, "switchport trunk native vlan ") {
				port.NativeVLAN = strings.TrimPrefix(stripped, "switchport trunk native vlan ")
			}
			if strings.HasPrefix(stripped, "switchport trunk allowed vlan ") {
				port.AllowedVLANs = strings.TrimPrefix(stripped, "switchport trunk allowed vlan ")
			}
		case "dhcp":
			switch {
			case strings.HasPrefix(stripped, "address-range "):
				pool.AddressRange = strings.TrimPrefix(stripped, "address-range ")
			case strings.HasPrefix(stripped, "network "):
				pool.Network = strings.TrimPrefix(stripped, "network ")
			case strings.HasPrefix(stripped, "default-router "):
				pool.Router = strings.TrimPrefix(stripped, "default-router ")
			case strings.HasPrefix(stripped, "dns-server "):
				pool.DNS = strings.TrimPrefix(stripped, "dns-server ")
			case strings.HasPrefix(stripped, "lease "):
				pool.Lease = formatLease(strings.TrimPrefix(stripped, "lease "))
			case strings.HasPrefix(stripped, "domain-name "):
				pool.Domain = strings.TrimPrefix(stripped, "domain-name ")
			default:
				if b, ok := parseBindLine(stripped, pool.Pool); ok {
					pool.Bindings = append(pool.Bindings, b)
				}
			}
		}
	}
	flush()
	return out
}

var ansiRE = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)
var cpuLineRE = regexp.MustCompile(`CPU:\s+(\d+)% usr\s+(\d+)% sys\s+(\d+)% nic\s+(\d+)% idle\s+(\d+)% io\s+(\d+)% irq\s+(\d+)% sirq`)
var loadLineRE = regexp.MustCompile(`Load average:\s+([0-9.]+)\s+([0-9.]+)\s+([0-9.]+)`)

type CPU struct {
	UserPct    int    `json:"user_pct"`
	SysPct     int    `json:"sys_pct"`
	NicePct    int    `json:"nice_pct"`
	IdlePct    int    `json:"idle_pct"`
	IOPct      int    `json:"io_pct"`
	IRQPct     int    `json:"irq_pct"`
	SoftIRQPct int    `json:"softirq_pct"`
	UsedPct    int    `json:"used_pct"`
	Load1      string `json:"load1,omitempty"`
	Load5      string `json:"load5,omitempty"`
	Load15     string `json:"load15,omitempty"`
}

func ParseTop(raw string) CPU {
	body := ansiRE.ReplaceAllString(stripCLI(raw, "service show top"), "")
	var out CPU
	if m := cpuLineRE.FindStringSubmatch(body); m != nil {
		out.UserPct, _ = strconv.Atoi(m[1])
		out.SysPct, _ = strconv.Atoi(m[2])
		out.NicePct, _ = strconv.Atoi(m[3])
		out.IdlePct, _ = strconv.Atoi(m[4])
		out.IOPct, _ = strconv.Atoi(m[5])
		out.IRQPct, _ = strconv.Atoi(m[6])
		out.SoftIRQPct, _ = strconv.Atoi(m[7])
		used := 100 - out.IdlePct
		if used < 0 {
			used = 0
		}
		out.UsedPct = used
	}
	if m := loadLineRE.FindStringSubmatch(body); m != nil {
		out.Load1, out.Load5, out.Load15 = m[1], m[2], m[3]
	}
	return out
}

type ConntrackFlow struct {
	Protocol    string `json:"protocol"`
	TTL         string `json:"ttl"`
	OriginSrc   string `json:"origin_src"`
	OriginDst   string `json:"origin_dst"`
	SrcPort     string `json:"src_port"`
	DstPort     string `json:"dst_port"`
	TxPackets   int64  `json:"tx_packets"`
	TxBytes     int64  `json:"tx_bytes"`
	RxPackets   int64  `json:"rx_packets"`
	RxBytes     int64  `json:"rx_bytes"`
	NatedIP     string `json:"nated_ip,omitempty"`
	NatedPort   string `json:"nated_port,omitempty"`
	TCPState    string `json:"tcp_state,omitempty"`
	Direction   string `json:"direction,omitempty"`
	Application string `json:"application,omitempty"`
	HostName    string `json:"host_name,omitempty"`
}

func ParseConntrackFlows(raw string) []ConntrackFlow {
	var rows []ConntrackFlow
	for _, line := range strings.Split(stripCLI(raw, "show conntrack"), "\n") {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "=") || strings.HasPrefix(s, "Connection") || strings.HasPrefix(s, "Protocol") {
			continue
		}
		parts := strings.Split(s, "|")
		if len(parts) < 15 {
			continue
		}
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		proto := strings.ToUpper(parts[0])
		if proto != "TCP" && proto != "UDP" && proto != "ICMP" && proto != "GRE" {
			continue
		}
		txp, _ := strconv.ParseInt(parts[6], 10, 64)
		txb, _ := strconv.ParseInt(parts[7], 10, 64)
		rxp, _ := strconv.ParseInt(parts[8], 10, 64)
		rxb, _ := strconv.ParseInt(parts[9], 10, 64)
		host := ""
		if len(parts) > 15 {
			host = strings.TrimSpace(strings.Join(parts[15:], " "))
		}
		natedPort := parts[11]
		if natedPort == "0" {
			natedPort = ""
		}
		state := parts[12]
		if state == "N/A" {
			state = ""
		}
		rows = append(rows, ConntrackFlow{
			Protocol: parts[0], TTL: parts[1], OriginSrc: parts[2], OriginDst: parts[3],
			SrcPort: parts[4], DstPort: parts[5], TxPackets: txp, TxBytes: txb,
			RxPackets: rxp, RxBytes: rxb, NatedIP: parts[10], NatedPort: natedPort,
			TCPState: state, Direction: parts[13], Application: parts[14], HostName: host,
		})
	}
	return rows
}
