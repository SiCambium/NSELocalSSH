package nse

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"nse-cli/internal/vpndiag"
)

// fakeRunner stands in for the SSH client so the adapter is testable offline.
// Keyed by command; an absent command is a device rejection, which is how this
// CLI answers anything it does not recognise.
type fakeRunner struct {
	out  map[string]string
	errs map[string]error
	seen []string
}

func (f *fakeRunner) run(cmd string, _ time.Duration) (string, error) {
	f.seen = append(f.seen, cmd)
	if err, ok := f.errs[cmd]; ok {
		return "", err
	}
	if v, ok := f.out[cmd]; ok {
		return v, nil
	}
	return cmd + "\n%Error processing cli command\nNSE-00009C(config)# ", nil
}

func sourceWith(f *fakeRunner) *sshEvidenceSource {
	return &sshEvidenceSource{run: f.run, cache: map[string]vpndiag.SourceResult{}}
}

func readCapture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Skipf("capture %s not present: %v", name, err)
	}
	return string(b)
}

// TestEvidenceNoSecretsReachTheAssembledState is the one test here that must
// never be skipped or weakened. The assembled state is sent off the device when
// advisory diagnosis is enabled, and `show config` carries cleartext PSKs for
// every site-to-site tunnel.
func TestEvidenceNoSecretsReachTheAssembledState(t *testing.T) {
	// A config stanza carrying real-looking secrets, not the pre-redacted form
	// the API returns — otherwise this test would pass trivially.
	cfg := `show config
site-to-site-vpn
 vpn ipsec 1
   name azure
   remote-address 198.51.100.9
   remote-subnets 10.1.0.0/16
   remote-psk SUPERSECRETPSKVALUE1234
   local-psk $crypt$1$ANOTHERSECRETVALUE
   exit
!
management user admin password $crypt$0$ADMINHASHVALUE
radius-server client-list 1
 name Demo
 secret RADIUSSHAREDSECRET
!
vpn-client
 wireguard private-key VEVTVC1QUklWQVRFLUtFWS1CQVNFNjQtVkFMVUU=
!
NSE-00009C(config)# `

	f := &fakeRunner{out: map[string]string{
		"show config":                 cfg,
		"service show debug-logs vpn": readCapture(t, "service_show_debug_logs_vpn.txt"),
	}}
	tree, err := vpndiag.LoadFS(vpndiag.Playbooks(), vpndiag.DocS2S)
	if err != nil {
		t.Fatal(err)
	}
	state, _, err := tree.GatherState(sourceWith(f), "azure")
	if err != nil {
		t.Fatal(err)
	}

	for _, secret := range []string{
		"SUPERSECRETPSKVALUE1234",
		"ANOTHERSECRETVALUE",
		"ADMINHASHVALUE",
		"RADIUSSHAREDSECRET",
		"VEVTVC1QUklWQVRFLUtFWS1CQVNFNjQtVkFMVUU=",
	} {
		if strings.Contains(state, secret) {
			t.Errorf("secret %q reached the assembled evidence, which is sent off the device", secret)
		}
	}
	if !strings.Contains(state, "<redacted>") {
		t.Error("expected redaction markers — if none are present the secrets were dropped by accident, not by design")
	}
	// The non-secret config that makes the tunnel diagnosable must survive.
	for _, want := range []string{"name azure", "remote-address 198.51.100.9", "remote-subnets 10.1.0.0/16"} {
		if !strings.Contains(state, want) {
			t.Errorf("redaction removed evidence that is not a secret: %q missing", want)
		}
	}
}

// TestEvidenceEmptyStatisticsIsAFindingNotAnAbsence covers the distinction the
// whole SourceResult.Available flag exists for. This device prints nothing at
// all when a tunnel has no SA, so the state must say "no SA records" — if it
// were blank, the root node would read a confident "no SA installed" for a
// reason indistinguishable from "this platform cannot tell you".
func TestEvidenceEmptyStatisticsIsAFindingNotAnAbsence(t *testing.T) {
	f := &fakeRunner{out: map[string]string{
		// Exactly what the live device returned: echo, then the prompt.
		s2sStatsCommandPrefix + " azure": s2sStatsCommandPrefix + " azure\nNSE-00009C(config)# ",
	}}
	got, err := sourceWith(f).Read("swanctl_list_sas", "azure")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Available {
		t.Fatal("empty statistics is a real answer, so the source must report as available")
	}
	if !strings.Contains(got.Text, "no SA records") {
		t.Errorf("text = %q, want an explicit no-SA statement rather than blank", got.Text)
	}
	if !got.PreScoped {
		t.Error("the command was scoped by passing the tunnel name, so the result must be marked pre-scoped")
	}
	if !strings.Contains(got.Note, "5 minutes") {
		t.Errorf("the staleness of this snapshot must be recorded: %q", got.Note)
	}
}

// TestEvidenceRejectsCLIErrorsAsEvidence covers the Run() trap: a rejected
// command returns a nil error with "%Error processing cli command" as ordinary
// output. Without an explicit check that error text becomes "evidence".
func TestEvidenceRejectsCLIErrorsAsEvidence(t *testing.T) {
	f := &fakeRunner{} // every command falls through to the %Error default
	_, err := sourceWith(f).Read("s2s_vpn_log", "azure")
	if err == nil {
		t.Fatal("a device rejection must surface as an error, not as evidence text")
	}
	if !strings.Contains(err.Error(), "rejected") {
		t.Errorf("error should say the device rejected the command: %v", err)
	}
}

// TestEvidenceUnknownSourceIsUnavailable covers a playbook asking for something
// this platform has no answer for.
func TestEvidenceUnknownSourceIsUnavailable(t *testing.T) {
	got, err := sourceWith(&fakeRunner{}).Read("wg_showconf_wg0", "peer1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Available {
		t.Error("an unmapped source must report unavailable rather than empty text")
	}
}

// TestEvidenceCachesRepeatedSources matters because three logical sources map
// onto two commands, and every SSH read holds the client's global lock.
func TestEvidenceCachesRepeatedSources(t *testing.T) {
	stats := s2sStatsCommandPrefix + " azure"
	f := &fakeRunner{out: map[string]string{stats: stats + "\nNSE-00009C(config)# "}}
	src := sourceWith(f)
	for i := 0; i < 3; i++ {
		if _, err := src.Read("swanctl_list_sas", "azure"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := src.Read("swanctl_counters", "azure"); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, c := range f.seen {
		if c == stats {
			n++
		}
	}
	if n != 2 {
		t.Errorf("ran the statistics command %d times; want 2 (once per distinct source name, cached thereafter)", n)
	}
}

func TestIPsecTunnelNamesFromCapture(t *testing.T) {
	names := IPsecTunnelNames(readCapture(t, "show_config_ipsec.txt"))
	if len(names) != 1 || names[0] != "azure" {
		t.Errorf("names = %q, want [azure]", names)
	}
}

// TestIPsecStanzasNameIsOnAChildLine pins why the playbook's generic
// block-header enumeration cannot be used here: the tunnel's name is a child
// leaf, not part of the `vpn ipsec N` header.
func TestIPsecStanzasNameIsOnAChildLine(t *testing.T) {
	cfg := `site-to-site-vpn
 vpn ipsec 1
   name first
   remote-address 198.51.100.1
   exit
!
site-to-site-vpn
 vpn ipsec 2
   name second-with-hyphen
   remote-address 198.51.100.2
   exit
!`
	got := ipsecStanzas(cfg)
	if len(got) != 2 {
		t.Fatalf("parsed %d stanzas, want 2: %v", len(got), keysOfMap(got))
	}
	if !strings.Contains(got["first"], "remote-address 198.51.100.1") {
		t.Errorf("first stanza wrong: %q", got["first"])
	}
	if !strings.Contains(got["second-with-hyphen"], "198.51.100.2") {
		t.Errorf("second stanza wrong: %q", got["second-with-hyphen"])
	}
	// A header-only lookup would find "vpn ipsec 1", never "first".
	if _, ok := got["vpn ipsec 1"]; ok {
		t.Error("stanzas must be keyed by the name leaf, not the block header")
	}
}

func keysOfMap(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestVPNDiagnoseBlocksCrossOrigin(t *testing.T) {
	s := &Server{Client: NewClient(Config{}), SkipConnect: true}
	req := httptest.NewRequest(http.MethodPost, "/api/vpn/diagnose", strings.NewReader(`{"tunnel":"azure"}`))
	req.Header.Set("Origin", "http://evil.example")
	rec := httptest.NewRecorder()
	s.handleVPNDiagnose(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

// TestVPNDiagnoseRejectsCommandInjection covers the tunnel name being
// interpolated into a CLI command.
func TestVPNDiagnoseRejectsCommandInjection(t *testing.T) {
	s := &Server{Client: NewClient(Config{}), SkipConnect: true}
	for _, bad := range []string{"azure; save", "azure\nsave", "azure | save", "azure & save", ""} {
		body := `{"tunnel":` + jsonQuote(bad) + `}`
		req := httptest.NewRequest(http.MethodPost, "/api/vpn/diagnose", strings.NewReader(body))
		req.Header.Set("Origin", "http://127.0.0.1")
		req.Host = "127.0.0.1"
		rec := httptest.NewRecorder()
		s.handleVPNDiagnose(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("tunnel %q: code %d, want 400 — body %s", bad, rec.Code, rec.Body.String())
		}
	}
}

func jsonQuote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`)
	return `"` + r.Replace(s) + `"`
}

// TestVPNDiagnoseRejectsGET pins the method check: this endpoint takes the SSH
// lock and can spend money, so it must not be reachable by navigation.
func TestVPNDiagnoseRejectsGET(t *testing.T) {
	s := &Server{Client: NewClient(Config{}), SkipConnect: true}
	rec := httptest.NewRecorder()
	s.handleVPNDiagnose(rec, httptest.NewRequest(http.MethodGet, "/api/vpn/diagnose", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("code %d, want 405", rec.Code)
	}
}

// TestJevClientNotConfiguredByDefault pins the default posture: with no key in
// the environment nothing can be sent anywhere.
func TestJevClientNotConfiguredByDefault(t *testing.T) {
	t.Setenv("OPENROUTER_API_KEY", "")
	s := &Server{Client: NewClient(Config{}), SkipConnect: true}
	if s.jevClient().Configured() {
		t.Error("with no key set, the decision client must report unconfigured")
	}
	if _, err := s.jevClient().Decide(nil, "state", map[string]vpndiag.Question{ //nolint:staticcheck
		"n": {Type: "noul", Instructions: "?", Criteria: map[string]string{"true": "t"}},
	}); !errors.Is(err, vpndiag.ErrNotConfigured) {
		t.Errorf("Decide without a key = %v, want ErrNotConfigured", err)
	}
}

// TestPrefsVPNDiagnoseDefaultsOff pins that egress is opt-in. Prefs' zero value
// is the "no egress" state, matching IPLookup.
func TestPrefsVPNDiagnoseDefaultsOff(t *testing.T) {
	if (Prefs{}).VPNDiagnose {
		t.Error("VPNDiagnose must default to false — this is the only outbound request carrying device output")
	}
	// A missing or unreadable prefs file must also read as off.
	if ReadPrefs(filepath.Join(t.TempDir(), "absent.json")).VPNDiagnose {
		t.Error("a missing prefs file must read as off")
	}
}

// TestStaleSnapshotNoteIsAttached guards the staleness warning. The SA view is a
// ~5 minute snapshot while the log is live, so a diagnosis reading both must be
// told which is which or it will silently reconcile a contradiction that is
// really clock skew.
func TestStaleSnapshotNoteIsAttached(t *testing.T) {
	if !regexp.MustCompile(`(?i)5 minutes`).MatchString(staleSnapshotNote) {
		t.Errorf("the note should state the refresh interval: %q", staleSnapshotNote)
	}
	if !strings.Contains(staleSnapshotNote, "log is authoritative") {
		t.Errorf("the note should say which source wins on disagreement: %q", staleSnapshotNote)
	}
}
