package vpndiag

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// mapSource is an EvidenceSource backed by literals. Anything absent from the
// map reports available=false rather than empty text — the distinction the
// interface exists for.
type mapSource struct {
	data map[string]string
	fail map[string]error
}

func (m mapSource) Read(name, scope string) (SourceResult, error) {
	if err, ok := m.fail[name]; ok {
		return SourceResult{}, err
	}
	text, ok := m.data[name]
	return SourceResult{Text: text, Available: ok}, nil
}

// realVPNLog returns the log captured from a live device, or skips.
func realVPNLog(t *testing.T) string {
	t.Helper()
	p := filepath.Join("..", "nse", "testdata", "service_show_debug_logs_vpn.txt")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Skipf("capture not present: %v", err)
	}
	return string(b)
}

// TestLogEventsAgainstRealCapture runs the shipped s2s playbook's own log
// declaration over output captured from a live NSE, so the regex, the JSONL
// field names and the dedup are all verified against the real thing rather than
// a fixture written to match the code.
func TestLogEventsAgainstRealCapture(t *testing.T) {
	tree := loadShipped(t, DocS2S)
	if len(tree.Evidence.LogSources) != 1 {
		t.Fatalf("expected one log source, got %d", len(tree.Evidence.LogSources))
	}
	src := tree.Evidence.LogSources[0]

	raw := realVPNLog(t)
	events, err := LogEvents(raw, src, "azure", tree.Evidence.MaxLogEvents)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 {
		t.Fatal("no events matched the real capture — the playbook's event_regex or field names are wrong")
	}

	// Dedup must collapse repeats. The capture holds several instances of each
	// template, so every returned event should carry a count above one.
	joined := ""
	for _, e := range events {
		joined += e.Template + "\n"
		if e.Count < 2 {
			t.Errorf("template %q counted %d — the capture repeats each one, so dedup did not collapse them",
				e.Template, e.Count)
		}
		if e.First == "" {
			t.Errorf("template %q has no timestamp", e.Template)
		}
	}

	// The lines that actually name the cause must survive the budget. This is
	// the failure mode dedup exists to prevent: without normalisation, repeats
	// of "sending packet ... (N bytes)" crowd these out.
	for _, want := range []string{"giving up after", "peer not responding"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the diagnostic event %q did not survive: got\n%s", want, joined)
		}
	}

	// Volatile tokens must be normalised away, or repeats would not converge.
	if strings.Contains(joined, "(464 bytes)") {
		t.Error("byte counts should be normalised to (N bytes)")
	}
	if regexp.MustCompile(`retransmit \d+ of`).MatchString(joined) {
		t.Error("retransmit counters should be normalised to N")
	}
}

// TestLogEventsScopeFallback covers the device firmware bug: when ikesa-name is
// nil the NSE emits the literal Go format-string error "%!s(<nil>)" as the
// scope, and the tunnel name then appears only in the message body. Matching on
// the scope field alone silently drops those events.
func TestLogEventsScopeFallback(t *testing.T) {
	src := loadShipped(t, DocS2S).Evidence.LogSources[0]
	raw := `{"level":"debug","msg":"log event: level: 1, ikesa-name: %!s(<nil>), msg: vici initiate CHILD_SA 'azure' ","time":"2026-09-27T08:13:54+05:30"}
{"level":"debug","msg":"log event: level: 1, ikesa-name: azure, msg: giving up after 5 retransmits ","time":"2026-09-27T08:14:00+05:30"}
{"level":"debug","msg":"log event: level: 1, ikesa-name: other, msg: unrelated tunnel event ","time":"2026-09-27T08:14:01+05:30"}`

	events, err := LogEvents(raw, src, "azure", 60)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range events {
		got = append(got, e.Template)
	}
	joined := strings.Join(got, " | ")
	if !strings.Contains(joined, "vici initiate CHILD_SA 'azure'") {
		t.Errorf("the %%!s(<nil>)-scoped event naming azure in its body must be kept: %s", joined)
	}
	if !strings.Contains(joined, "giving up after 5 retransmits") {
		t.Errorf("the correctly-scoped event must be kept: %s", joined)
	}
	if strings.Contains(joined, "unrelated tunnel event") {
		t.Errorf("another tunnel's event must NOT be kept: %s", joined)
	}
}

func TestNormalizeTemplate(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"initiating IKE_SA azure[17] to 1.2.3.4", "initiating IKE_SA azure to 1.2.3.4"},
		{"retransmit 5 of request with message ID 0", "retransmit N of request with message ID N"},
		{"peer not responding, trying again (3/0)", "peer not responding, trying again (N/M)"},
		{"sending packet: from a to b (464 bytes)", "sending packet: from a to b (N bytes)"},
		{"collapse    runs   of spaces", "collapse runs of spaces"},
		{"  trimmed  ", "trimmed"},
	} {
		if got := NormalizeTemplate(tc.in); got != tc.want {
			t.Errorf("NormalizeTemplate(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestSplitBlocksIgnoresIndentedHeaders pins the column-zero rule. An indented
// line matching the header pattern belongs to the current block — that is what
// keeps a nested child record from being read as a new block.
func TestSplitBlocksIgnoresIndentedHeaders(t *testing.T) {
	re := regexp.MustCompile(`^(?P<name>\S.*?): `)
	text := `preamble line
alpha: first
  alpha: still inside alpha, indented
beta: second
  detail`
	blocks, order, preamble := SplitBlocks(text, re)

	if len(order) != 2 || order[0] != "alpha" || order[1] != "beta" {
		t.Fatalf("order = %q, want [alpha beta]", order)
	}
	if len(preamble) != 1 || preamble[0] != "preamble line" {
		t.Errorf("preamble = %q", preamble)
	}
	if n := len(blocks["alpha"]); n != 2 {
		t.Errorf("alpha has %d lines, want 2 — the indented match must not open a block", n)
	}
	if n := len(blocks["beta"]); n != 2 {
		t.Errorf("beta has %d lines, want 2", n)
	}
}

// TestGatherStateNamesUnavailableSources is the correctness point that matters
// most here. Three of the s2s playbook's four declared sources cannot run on
// this platform. If they simply came back blank, a missing SA table would read
// as "no SA is installed" — a confidently wrong answer that sends the walk down
// the wrong branch. The state must say the source was unavailable instead.
func TestGatherStateNamesUnavailableSources(t *testing.T) {
	tree := loadShipped(t, DocS2S)
	src := mapSource{data: map[string]string{
		// Only the log is supplied; every command source is absent.
		"s2s_vpn_log": `{"level":"debug","msg":"log event: level: 1, ikesa-name: azure, msg: giving up after 5 retransmits ","time":"2026-09-27T08:14:00+05:30"}`,
	}}

	state, notes, err := tree.GatherState(src, "azure")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(state, "--- tunnel: azure ---") {
		t.Errorf("state should open with the scope header:\n%s", state)
	}
	if !strings.Contains(state, "not available on this platform") {
		t.Errorf("an unavailable source must be named as such, not left blank:\n%s", state)
	}
	if !strings.Contains(state, "not evidence of absence") {
		t.Error("the state should say explicitly that unavailable is not the same as absent")
	}
	if !strings.Contains(state, "giving up after 5 retransmits") {
		t.Errorf("the log events should be present:\n%s", state)
	}
	if len(notes) == 0 {
		t.Error("unavailable sources should be reported in notes as well as in the state")
	}
}

// TestGatherStateReportsReadErrors covers a source that fails rather than being
// absent. Both end up labelled, but a read error is a different fact.
func TestGatherStateReportsReadErrors(t *testing.T) {
	tree := loadShipped(t, DocS2S)
	src := mapSource{
		data: map[string]string{},
		fail: map[string]error{"swanctl_list_sas": errors.New("ssh timed out")},
	}
	_, notes, err := tree.GatherState(src, "azure")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(notes, " | ")
	if !strings.Contains(joined, "ssh timed out") {
		t.Errorf("a read error should surface in notes: %s", joined)
	}
}

// TestGatherStateTruncatesOnALineBoundary covers the state budget. Cutting
// mid-line would leave a half-record that looks like real but malformed
// evidence, so the cut is made at a newline and announced.
func TestGatherStateTruncatesOnALineBoundary(t *testing.T) {
	tree := loadShipped(t, DocS2S)
	tree.Evidence.MaxStateChars = 200

	var b strings.Builder
	for i := 0; i < 400; i++ {
		b.WriteString(`{"level":"debug","msg":"log event: level: 1, ikesa-name: azure, msg: event number `)
		b.WriteString(strings.Repeat("x", 20))
		b.WriteString(` ","time":"2026-09-27T08:14:00+05:30"}` + "\n")
	}
	src := mapSource{data: map[string]string{"s2s_vpn_log": b.String()}}

	state, notes, err := tree.GatherState(src, "azure")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(state, "[evidence truncated") {
		t.Errorf("truncation must be announced in the state itself:\n%s", state)
	}
	if !strings.Contains(strings.Join(notes, " "), "truncated") {
		t.Error("truncation should also appear in notes")
	}
	// The announcement is appended after the cut, so allow for its length.
	if len(state) > tree.Evidence.MaxStateChars+80 {
		t.Errorf("state is %d chars, budget %d", len(state), tree.Evidence.MaxStateChars)
	}
}

// TestScopeCmdSourceBlockMissIsNamed covers the difference between "there is no
// block for this tunnel" and "the block was empty". Conflating them would hide
// which of the two actually happened.
func TestScopeCmdSourceBlockMissIsNamed(t *testing.T) {
	cs := CmdSource{
		File:             "x",
		Scope:            "block",
		BlockHeaderRegex: `^(?P<name>\S.*?): `,
	}
	got, err := scopeCmdSource("alpha: one\nbeta: two", cs, "gamma")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `no block matching "gamma"`) {
		t.Errorf("a scope miss must be named: %q", got)
	}
}

func TestScopeCmdSourceGrepAndNone(t *testing.T) {
	text := "keep this line\ndrop that one\nkeep this too"
	grep := CmdSource{Scope: "grep", GrepRegex: `^keep`}
	got, err := scopeCmdSource(text, grep, "ignored")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "drop that one") || strings.Count(got, "keep") != 2 {
		t.Errorf("grep = %q", got)
	}

	for _, scope := range []string{"none", "all", ""} {
		got, err := scopeCmdSource(text, CmdSource{Scope: scope}, "ignored")
		if err != nil {
			t.Fatal(err)
		}
		if got != text {
			t.Errorf("scope %q should pass everything through", scope)
		}
	}
}

// TestSourceNameStripsGlob pins the file-vs-command mismatch. A log source is
// declared as "s2s_vpn_log*" (a file pattern, because upstream reads rotated
// files from a techdump) while live_commands is keyed "s2s_vpn_log". Reading the
// glob verbatim finds nothing, which then looks identical to a source the
// platform does not support — a silent wrong answer rather than a loud one.
func TestSourceNameStripsGlob(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"s2s_vpn_log*", "s2s_vpn_log"},
		{"s2s_vpn_log", "s2s_vpn_log"},
		{"wg_show", "wg_show"},
		{"log?", "log"},
	} {
		if got := SourceName(tc.in); got != tc.want {
			t.Errorf("SourceName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	// And end to end: the shipped playbook's declared log ref must resolve to a
	// key that exists in its own live_commands map.
	tree := loadShipped(t, DocS2S)
	for _, ls := range tree.Evidence.LogSources {
		name := SourceName(ls.File)
		if _, ok := tree.Evidence.LiveCommands[name]; !ok {
			t.Errorf("log source %q resolves to %q, which is not in live_commands %v",
				ls.File, name, keysOf(tree.Evidence.LiveCommands))
		}
	}
	for _, cs := range tree.Evidence.CmdSources {
		name := SourceName(cs.File)
		if _, ok := tree.Evidence.LiveCommands[name]; !ok {
			t.Errorf("cmd source %q resolves to %q, which is not in live_commands %v",
				cs.File, name, keysOf(tree.Evidence.LiveCommands))
		}
	}
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
