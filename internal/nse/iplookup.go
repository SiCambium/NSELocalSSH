package nse

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// IPOrgInfo is the "who owns this address" summary shown next to a
// conn-tracking flow's destination IP.
type IPOrgInfo struct {
	IP      string `json:"ip"`
	Org     string `json:"org"`
	ISP     string `json:"isp"`
	Country string `json:"country"`
	City    string `json:"city"`
	ASN     string `json:"asn"`
}

type ipOrgCacheEntry struct {
	info      IPOrgInfo
	fetchedAt time.Time
}

// ipOrgCacheTTL is long because an IP's owning organization essentially
// never changes minute-to-minute — this is what keeps lookups well
// within ipwho.is's free tier even with the conn-tracking table polling
// every few seconds.
const ipOrgCacheTTL = 24 * time.Hour

// ipOrgCache is a process-lifetime cache of IP -> organization lookups.
type ipOrgCache struct {
	mu      sync.Mutex
	entries map[string]ipOrgCacheEntry
}

func newIPOrgCache() *ipOrgCache {
	return &ipOrgCache{entries: make(map[string]ipOrgCacheEntry)}
}

func (c *ipOrgCache) get(ip string) (IPOrgInfo, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[ip]
	if !ok || time.Since(e.fetchedAt) > ipOrgCacheTTL {
		return IPOrgInfo{}, false
	}
	return e.info, true
}

func (c *ipOrgCache) set(ip string, info IPOrgInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[ip] = ipOrgCacheEntry{info: info, fetchedAt: time.Now()}
}

// LookupIPOrg resolves a public IP address to its owning organization/ISP
// via ipwho.is (free, no API key, HTTPS), caching results for
// ipOrgCacheTTL so a busy conn-tracking table doesn't re-query the same
// address on every poll. Private/loopback/link-local addresses are
// rejected before any network call, since they never resolve usefully
// and would just waste the free-tier budget.
func (c *ipOrgCache) LookupIPOrg(ip string) (IPOrgInfo, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return IPOrgInfo{}, fmt.Errorf("invalid IP address")
	}
	if parsed.IsPrivate() || parsed.IsLoopback() || parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast() {
		return IPOrgInfo{}, fmt.Errorf("private address, nothing to look up")
	}
	if cached, ok := c.get(ip); ok {
		return cached, nil
	}

	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://ipwho.is/" + ip)
	if err != nil {
		return IPOrgInfo{}, fmt.Errorf("lookup request failed: %w", err)
	}
	defer resp.Body.Close()

	var raw struct {
		Success    bool   `json:"success"`
		Message    string `json:"message"`
		Country    string `json:"country"`
		City       string `json:"city"`
		Connection struct {
			ASN int    `json:"asn"`
			Org string `json:"org"`
			ISP string `json:"isp"`
		} `json:"connection"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return IPOrgInfo{}, fmt.Errorf("lookup response decode failed: %w", err)
	}
	if !raw.Success {
		return IPOrgInfo{}, fmt.Errorf("lookup failed: %s", strings.TrimSpace(raw.Message))
	}

	info := IPOrgInfo{
		IP:      ip,
		Org:     raw.Connection.Org,
		ISP:     raw.Connection.ISP,
		Country: raw.Country,
		City:    raw.City,
	}
	if raw.Connection.ASN != 0 {
		info.ASN = fmt.Sprintf("AS%d", raw.Connection.ASN)
	}
	c.set(ip, info)
	return info, nil
}

func (s *Server) ipOrgCacheInstance() *ipOrgCache {
	s.ipOrgCacheOnce.Do(func() {
		s.ipOrgCache = newIPOrgCache()
	})
	return s.ipOrgCache
}

// handleIPLookup looks up who owns a public IP address, gated behind the
// ip_lookup preference — off by default, since this is the one endpoint
// in this app that sends anything (just the address itself) to a third
// party rather than talking only to the device over SSH.
func (s *Server) handleIPLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !ReadPrefs(s.prefsFile()).IPLookup {
		writeSettingsError(w, http.StatusForbidden, "IP lookup is turned off — enable it on the Conn tracking tab first")
		return
	}
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if ip == "" {
		writeSettingsError(w, http.StatusBadRequest, "ip is required")
		return
	}
	info, err := s.ipOrgCacheInstance().LookupIPOrg(ip)
	if err != nil {
		writeSettingsError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, info)
}
