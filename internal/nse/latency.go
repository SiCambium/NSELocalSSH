package nse

import (
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"
)

// WAN latency, measured the way the device already measures it.
//
// Every WAN carries a list of load-balance monitor hosts in its running
// config — the addresses the device itself pings to decide whether that
// link is alive. Charting the round-trip to those exact hosts is
// therefore not an invented metric: it is the number the failover
// decision is already being made on.
//
// Sampling is on demand and rate limited rather than run from a
// background ticker. A ping holds the shared SSH lock for its whole
// duration, so a timer firing three of them would put a multi-second
// stall into whatever dashboard poll happened to be next. Asking only
// when someone is looking, and at most once a minute, keeps that cost
// where the user can see what they are paying for.
const latencyMinInterval = time.Minute

// pingAvgRE pulls the middle figure out of "round-trip min/avg/max =
// 1.333/1.422/1.502 ms".
var pingAvgRE = regexp.MustCompile(`min/avg/max = ([0-9.]+)/([0-9.]+)/([0-9.]+)`)

// PingAverageMs returns the mean round-trip in milliseconds from a ping
// summary, and whether the summary carried one at all. A ping that lost
// every packet prints no min/avg/max line, which is the difference
// between "slow" and "gone" and must not collapse to zero.
func PingAverageMs(raw string) (float64, bool) {
	m := pingAvgRE.FindStringSubmatch(raw)
	if m == nil {
		return 0, false
	}
	v, err := strconv.ParseFloat(m[2], 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// LatencyReading is one monitor host as last measured.
type LatencyReading struct {
	WAN     string  `json:"wan"`
	Host    string  `json:"host"`
	AvgMs   float64 `json:"avg_ms"`
	LossPct string  `json:"loss_pct,omitempty"`
	OK      bool    `json:"ok"`
	Error   string  `json:"error,omitempty"`
}

type latencyCache struct {
	mu       sync.Mutex
	readings []LatencyReading
	at       time.Time
	// Newest log sample already folded into history, per series. The
	// device's log keeps printing the same lines until they age out, so
	// without this every read would fold the same measurement in again
	// and drag the bucket's mean toward whatever happened to repeat.
	seen map[string]time.Time
}

// ingestWANLB folds the device's own monitor-host measurements into the
// history store. Free: the balancer is already making them to decide
// whether each link is alive, and this only reads what it wrote.
// wanNames maps a physical port to the WAN it carries ("eth1" -> "wan1"),
// so the log's interface-keyed samples and this app's own WAN-keyed ones
// land on the same series instead of drawing the same link twice.
func wanNames(cfg CloudConfig) map[string]string {
	out := map[string]string{}
	for _, w := range cfg.WANInterfaces {
		if w.LANIntf != "" && w.Name != "" {
			out[w.LANIntf] = w.Name
		}
	}
	return out
}

func (s *Server) ingestWANLB(c *latencyCache, device string, names map[string]string) int {
	raw, err := s.Client.Run("service show debug-logs wanlb", 30*time.Second)
	if err != nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen == nil {
		c.seen = map[string]time.Time{}
	}
	added := 0
	for _, sample := range ParseWANLBLatency(raw) {
		name := names[sample.Iface]
		if name == "" {
			// A port with no WAN role in the running config: keep it
			// under its own name rather than dropping a measurement.
			name = sample.Iface
		}
		key := "lat:" + name + ":" + sample.Host
		if last, ok := c.seen[key]; ok && !sample.At.After(last) {
			continue
		}
		c.seen[key] = sample.At
		s.History.Record(device, key, sample.AvgMs, sample.MaxMs, sample.At)
		added++
	}
	return added
}

func (s *Server) handleLatency(w http.ResponseWriter, _ *http.Request) {
	s.latencyOnce.Do(func() { s.latency = &latencyCache{} })
	c := s.latency

	c.mu.Lock()
	fresh := time.Since(c.at) < latencyMinInterval && c.readings != nil
	cached := c.readings
	at := c.at
	c.mu.Unlock()

	if fresh {
		writeJSON(w, map[string]any{"readings": cached, "measured_at": at.Unix(), "cached": true})
		return
	}

	cfg, err := FetchCloudConfig(s.Client, 20*time.Second)
	if err != nil {
		writeDeviceError(w, err)
		return
	}

	// The cheap half: no packets are sent, and it brings measurements
	// from before this app was running. Done after the config read
	// because the samples have to be keyed by WAN name, which only the
	// running config knows.
	ingested := s.ingestWANLB(c, s.Client.Cfg.Host, wanNames(cfg))

	now := time.Now()
	readings := []LatencyReading{}
	for _, wan := range cfg.WANInterfaces {
		for _, host := range wan.LoadBalanceConfig.MonitorHosts {
			if host == "" {
				continue
			}
			r := LatencyReading{WAN: wan.Name, Host: host}
			out, err := s.Client.Run("ping "+host, 25*time.Second)
			if err != nil {
				r.Error = err.Error()
				readings = append(readings, r)
				continue
			}
			p := ParsePing(out)
			r.LossPct = p.LossPct
			if avg, ok := PingAverageMs(out); ok {
				r.AvgMs, r.OK = avg, true
				// Same store as throughput, so latency gets the same
				// windows and the same retention without a second
				// mechanism to keep in step.
				s.History.Record(s.Client.Cfg.Host, "lat:"+wan.Name+":"+host, avg, 0, now)
			}
			readings = append(readings, r)
		}
	}

	c.mu.Lock()
	c.readings, c.at = readings, now
	c.mu.Unlock()

	writeJSON(w, map[string]any{
		"readings":     readings,
		"measured_at":  now.Unix(),
		"cached":       false,
		"log_ingested": ingested,
	})
}
