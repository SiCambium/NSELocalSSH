package nse

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Management services: which ways into the device are open.
//
// These were deliberately left out when this app was written, on the
// reasoning that they gate the very access it depends on. That reasoning
// held while cnMaestro was there to turn them back on. It does not hold
// for a unit being commissioned without a cloud to fall back to: if this
// tool cannot open HTTPS on a new device, nothing local can.
//
// So they are here, behind the safe-apply path that exists for exactly
// this class of change: snapshot, apply, prove a brand-new SSH login
// still works, and hold the change unsaved until a human confirms it. A
// change that cuts access is never written to the startup config, so the
// device still boots the old one and a power cycle recovers.
//
// Every line below is CONFIRMED from a real `show config` capture
// (testdata/show_config_full.txt), negated forms included, which that
// capture carries as live lines:
//
//	management https            management https port 443
//	management http             management http port 80
//	management ssh              management ssh idle-timeout 300
//	no management telnet        no management radius-auth
func managementServiceLine(name string, enable bool) string {
	if enable {
		return "management " + name
	}
	return "no management " + name
}

func managementPortLine(name string, port int) string {
	return fmt.Sprintf("management %s port %d", name, port)
}

func managementSSHIdleTimeoutLine(seconds int) string {
	return fmt.Sprintf("management ssh idle-timeout %d", seconds)
}

type servicesRequest struct {
	Action  string `json:"action"`
	Service string `json:"service"`
	Enable  *bool  `json:"enable"`
	Port    *int   `json:"port"`
	Seconds *int   `json:"seconds"`
}

var manageableServices = map[string]bool{
	"ssh": true, "https": true, "http": true, "telnet": true, "radius-auth": true,
}

// servicesWithPorts is the subset the CLI gives a port leaf to. Asking
// for a port on anything else is a request error, not a command to send
// and let the device reject.
var servicesWithPorts = map[string]bool{"https": true, "http": true}

func (s *Server) handleConfigServices(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleGetConfigServices(w, r)
	case http.MethodPost:
		s.handlePostConfigServices(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGetConfigServices reads state straight from `show config`. A
// service is on when its bare line is present and off when the negated
// line is, which is how this CLI states booleans.
func (s *Server) handleGetConfigServices(w http.ResponseWriter, _ *http.Request) {
	raw, ok := s.cli(w, "show config", 25*time.Second)
	if !ok {
		return
	}
	state, ports, idle := parseManagementServices(raw)
	writeJSON(w, map[string]any{
		"services":         state,
		"ports":            ports,
		"ssh_idle_timeout": idle,
	})
}

func parseManagementServices(raw string) (map[string]bool, map[string]int, int) {
	tree := ParseBlockTree(raw)
	state := map[string]bool{}
	ports := map[string]int{}
	idle := 0
	for _, child := range tree.Children {
		if child.Block != nil {
			continue
		}
		line := strings.TrimSpace(child.Line)
		switch {
		case strings.HasPrefix(line, "management ssh idle-timeout "):
			idle, _ = strconv.Atoi(strings.TrimPrefix(line, "management ssh idle-timeout "))
		case strings.HasPrefix(line, "management ") && strings.Contains(line, " port "):
			f := strings.Fields(line)
			if len(f) == 4 {
				if p, err := strconv.Atoi(f[3]); err == nil {
					ports[f[1]] = p
				}
			}
		case strings.HasPrefix(line, "no management "):
			state[strings.TrimPrefix(line, "no management ")] = false
		case strings.HasPrefix(line, "management "):
			name := strings.TrimPrefix(line, "management ")
			if manageableServices[name] {
				state[name] = true
			}
		}
	}
	// A service the config mentions neither way is off: this CLI prints
	// the negated line for things it knows about, so silence means the
	// feature is not in play.
	for name := range manageableServices {
		if _, seen := state[name]; !seen {
			state[name] = false
		}
	}
	return state, ports, idle
}

func (s *Server) handlePostConfigServices(w http.ResponseWriter, r *http.Request) {
	if !isSameOrigin(r) {
		writeCrossOriginBlocked(w)
		return
	}
	var req servicesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSettingsError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	lines, errMsg := servicesLines(req)
	if errMsg != "" {
		writeSettingsError(w, http.StatusBadRequest, errMsg)
		return
	}

	outcome, err := s.safeApplier().Apply(ConfigBlock{
		Name:  "management service",
		Lines: lines,
		Risk:  ClassifyRisk("management-service"),
		Keys:  managementKeys(lines),
	})
	if err != nil {
		writeDeviceError(w, err)
		return
	}
	writeJSON(w, map[string]any{"outcome": outcome, "lines": lines})
}

// servicesLines validates a request and returns the lines to send, or the
// message explaining why nothing will be sent.
func servicesLines(req servicesRequest) ([]string, string) {
	switch req.Action {
	case "toggle":
		if !manageableServices[req.Service] {
			return nil, "unknown service"
		}
		if req.Enable == nil {
			return nil, "no state given"
		}
		// This app speaks SSH and nothing else. Turning SSH off through
		// it is not a risky change to be guarded, it is a request to
		// remove the channel the guard itself runs over: the reachability
		// probe would fail, the change would roll back, and the round
		// trip would have taught nobody anything. Refused, with the
		// alternative named.
		if req.Service == "ssh" && !*req.Enable {
			return nil, "this tool reaches the device over SSH only, so it cannot be the thing that turns SSH off. Do that from the console or the web interface, with another way in already proven."
		}
		return []string{managementServiceLine(req.Service, *req.Enable)}, ""

	case "port":
		if !servicesWithPorts[req.Service] {
			return nil, "this service has no port setting"
		}
		if req.Port == nil || *req.Port < 1 || *req.Port > 65535 {
			return nil, "port must be between 1 and 65535"
		}
		return []string{managementPortLine(req.Service, *req.Port)}, ""

	case "ssh_idle_timeout":
		// Zero is not known to mean "never", and guessing which it means
		// could leave a session open forever on a device in someone
		// else's rack.
		if req.Seconds == nil || *req.Seconds < 60 || *req.Seconds > 86400 {
			return nil, "timeout must be between 60 and 86400 seconds"
		}
		return []string{managementSSHIdleTimeoutLine(*req.Seconds)}, ""
	}
	return nil, "unknown action"
}

// managementKeys names the top-level leaves the rollback pre-image must
// carry. A toggle's pre-image is whichever of the two forms the device
// currently prints, so both are claimed.
func managementKeys(lines []string) []string {
	keys := make([]string, 0, len(lines)*2)
	for _, line := range lines {
		bare := strings.TrimPrefix(line, "no ")
		keys = append(keys, bare, "no "+bare)
	}
	return keys
}
