package vpndiag

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// The evidence block of a playbook declares which raw sources to read and how to
// scope and assemble them into the single text Jev reasons over.
//
// Everything here is generic over that declaration. What differs per platform is
// only which command supplies a named logical source, which is the
// EvidenceSource's job — the JSON is shared with an upstream implementation and
// must not be forked to describe one device's CLI.

// Evidence is the playbook's evidence declaration.
type Evidence struct {
	ScopeNoun     string            `json:"scope_noun"`
	LiveCommands  map[string]string `json:"live_commands"`
	MaxStateChars int               `json:"max_state_chars"`
	MaxLogEvents  int               `json:"max_log_events"`
	Enumerate     Enumerate         `json:"enumerate"`
	CmdSources    []CmdSource       `json:"cmd_sources"`
	LogSources    []LogSource       `json:"log_sources"`
}

// Enumerate declares how to list the scopes (tunnels, peers) in a source.
type Enumerate struct {
	File             string `json:"file"`
	BlockHeaderRegex string `json:"block_header_regex"`
	PeerRegex        string `json:"peer_regex"`
	SubnetRegex      string `json:"subnet_regex"`
}

// CmdSource is one command's output, included in the assembled state.
//
// Scope selects how it is narrowed: "block" keeps only the scoped entity's
// block, "grep" keeps matching lines globally, and "none"/"all"/"" includes
// everything.
type CmdSource struct {
	File             string `json:"file"`
	Label            string `json:"label"`
	Scope            string `json:"scope"`
	BlockHeaderRegex string `json:"block_header_regex"`
	IncludePreamble  bool   `json:"include_preamble"`
	GrepRegex        string `json:"grep_regex"`
}

// LogSource is a log, parsed and deduplicated rather than included verbatim.
//
// The field is spelled "file_glob" because upstream reads logs as files from a
// techdump, where the name may be a pattern ("s2s_vpn_log*" matching rotated
// files). On-box there is no file: the same logical name keys
// Evidence.LiveCommands, WITHOUT the glob. SourceName strips it.
type LogSource struct {
	File       string `json:"file_glob"`
	Kind       string `json:"kind"`
	MsgField   string `json:"msg_field"`
	TimeField  string `json:"time_field"`
	EventRegex string `json:"event_regex"`
	Label      string `json:"label"`
}

// SourceName turns a declared source reference into the logical name that keys
// Evidence.LiveCommands, by dropping glob metacharacters.
//
// Needed because a log source is declared as a file pattern ("s2s_vpn_log*")
// while the command map is keyed by the bare name ("s2s_vpn_log"). Reading the
// glob verbatim silently finds nothing, which then looks exactly like a source
// the platform does not support.
func SourceName(ref string) string {
	return strings.TrimRight(ref, "*?")
}

// SourceResult is one logical source, as an EvidenceSource resolved it.
type SourceResult struct {
	Text string

	// Available separates "this platform cannot supply this" from "it supplied
	// nothing". The distinction is load-bearing: a blank SA table reads to a
	// model as a confident "no SA is installed" rather than "cannot tell", which
	// sends the walk down the wrong branch with full confidence.
	Available bool

	// PreScoped means Text already covers only the requested scope, so no
	// further narrowing should be applied. On-box sources often get scoping for
	// free by passing the tunnel name to the command; applying the playbook's
	// block regex on top would then find no block and report a misleading miss,
	// because the regex describes a different platform's output shape.
	PreScoped bool

	// Note records provenance the model and the operator both need — most
	// importantly staleness, where one source is a periodic snapshot and
	// another is live.
	Note string
}

// EvidenceSource reads a named logical source for a given scope. The name is a
// key of Evidence.LiveCommands; an implementation decides how to produce it.
//
// Scope is passed in because a device command often takes the tunnel name as an
// argument, which is both cheaper and more accurate than fetching everything and
// filtering afterwards.
type EvidenceSource interface {
	Read(name, scope string) (SourceResult, error)
}

var (
	// dedupNorm collapses volatile tokens before events are counted, so
	// equivalent templates converge. Ported from the reference's _DEFAULT_NORM.
	//
	// This is what makes diagnosis work, not an optimisation. Deduplicating raw
	// lines instead lets sixty near-identical "initiating IKE_SA[1..60]" or
	// "sending packet: ... (464 bytes)" lines exhaust the event budget and crowd
	// out the one "giving up after 5 retransmits" line that names the cause.
	// Measured on a live device: 4,219 events collapsed to 7 templates.
	dedupNorm = []struct {
		re   *regexp.Regexp
		with string
	}{
		{regexp.MustCompile(`\[\d+\]`), ""},                              // SA / child indices
		{regexp.MustCompile(`(?i)message ID \d+`), "message ID N"},       //
		{regexp.MustCompile(`(?i)retransmit \d+ of`), "retransmit N of"}, //
		{regexp.MustCompile(`\(\d+/\d+\)`), "(N/M)"},                     // "trying again (3/0)"
		{regexp.MustCompile(`\(\d+ bytes\)`), "(N bytes)"},               //
		{regexp.MustCompile(`\s{2,}`), " "},
	}
)

// NormalizeTemplate collapses volatile tokens in an event so repeats converge.
func NormalizeTemplate(s string) string {
	for _, n := range dedupNorm {
		s = n.re.ReplaceAllString(s, n.with)
	}
	return strings.TrimSpace(s)
}

// SplitBlocks splits text into named blocks plus the text preceding the first
// one.
//
// A header is a line matching headerRE **at column zero**; an indented match
// belongs to the current block. That is what keeps nested child records (an
// indented CHILD_SA under its IKE_SA, say) from being read as new blocks.
func SplitBlocks(text string, headerRE *regexp.Regexp) (blocks map[string][]string, order []string, preamble []string) {
	blocks = map[string][]string{}
	current := ""
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r", ""), "\n") {
		indented := strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")
		if !indented {
			if m := headerRE.FindStringSubmatch(line); m != nil {
				name := namedGroup(headerRE, m, "name")
				if name == "" && len(m) > 1 {
					name = m[1]
				}
				name = strings.TrimSpace(name)
				if _, seen := blocks[name]; !seen {
					order = append(order, name)
				}
				current = name
				blocks[name] = append(blocks[name], line)
				continue
			}
		}
		if current == "" {
			preamble = append(preamble, line)
		} else {
			blocks[current] = append(blocks[current], line)
		}
	}
	return blocks, order, preamble
}

func namedGroup(re *regexp.Regexp, match []string, name string) string {
	for i, n := range re.SubexpNames() {
		if n == name && i < len(match) {
			return match[i]
		}
	}
	return ""
}

// LogEvent is one deduplicated event template.
type LogEvent struct {
	First    string // earliest timestamp seen for this template
	Template string
	Count    int
}

// LogEvents parses a log source and returns distinct event templates for one
// scope, oldest first.
//
// A line is kept when the event regex's "scope" group equals the scope name, or
// when the scope name appears in the matched event text. That second rule is not
// belt-and-braces: an NSE emits the literal Go format-string error
// "%!s(<nil>)" as the scope when its ikesa-name is nil, and the tunnel name then
// appears only in the message body. Without the fallback those events vanish.
func LogEvents(text string, src LogSource, scope string, limit int) ([]LogEvent, error) {
	var eventRE *regexp.Regexp
	if src.EventRegex != "" {
		re, err := regexp.Compile(src.EventRegex)
		if err != nil {
			return nil, fmt.Errorf("event_regex: %w", err)
		}
		eventRE = re
	}

	type agg struct {
		first string
		count int
	}
	seen := map[string]*agg{}

	for _, line := range strings.Split(strings.ReplaceAll(text, "\r", ""), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		msg, ts := line, ""
		if src.Kind == "jsonl" {
			m, t, ok := jsonLogFields(line, src.MsgField, src.TimeField)
			if !ok {
				continue
			}
			msg, ts = m, t
		}

		event := msg
		if eventRE != nil {
			m := eventRE.FindStringSubmatch(msg)
			if m == nil {
				continue
			}
			got := strings.TrimSpace(namedGroup(eventRE, m, "scope"))
			event = strings.TrimSpace(namedGroup(eventRE, m, "event"))
			if event == "" {
				event = msg
			}
			if scope != "" && got != scope && !strings.Contains(event, scope) {
				continue
			}
		} else if scope != "" && !strings.Contains(msg, scope) {
			continue
		}

		key := NormalizeTemplate(event)
		if key == "" {
			continue
		}
		a, ok := seen[key]
		if !ok {
			seen[key] = &agg{first: ts, count: 1}
			continue
		}
		a.count++
		// Keep the earliest timestamp so the order reflects when a template was
		// first seen, not when it last repeated.
		if ts != "" && (a.first == "" || ts < a.first) {
			a.first = ts
		}
	}

	out := make([]LogEvent, 0, len(seen))
	for tmpl, a := range seen {
		out = append(out, LogEvent{First: a.first, Template: tmpl, Count: a.count})
	}
	// Oldest first, then by template so the order is stable when timestamps tie
	// or are absent — an unstable state string would make runs incomparable.
	sort.Slice(out, func(i, j int) bool {
		if out[i].First != out[j].First {
			return out[i].First < out[j].First
		}
		return out[i].Template < out[j].Template
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// jsonLogFields pulls the message and timestamp out of one JSONL line without a
// struct, since the field names come from the playbook.
func jsonLogFields(line, msgField, timeField string) (msg, ts string, ok bool) {
	var obj map[string]any
	if err := jsonUnmarshalStrict(line, &obj); err != nil {
		return "", "", false
	}
	if msgField == "" {
		msgField = "msg"
	}
	if timeField == "" {
		timeField = "time"
	}
	m, _ := obj[msgField].(string)
	t, _ := obj[timeField].(string)
	if m == "" {
		return "", "", false
	}
	return m, t, true
}

// GatherState assembles the text Jev reasons over: a scope header, each command
// source scoped per its declaration, then each log source deduplicated.
//
// Content is included verbatim. It is the caller's job to have redacted secrets
// before this point — on a device whose `show config` carries cleartext PSKs
// that is not optional, and it is the one place this deliberately departs from
// the upstream spec's "keep it verbatim, do not summarize" instruction.
func (t *Tree) GatherState(src EvidenceSource, scope string) (string, []string, error) {
	var b strings.Builder
	var notes []string

	noun := t.Evidence.ScopeNoun
	if noun == "" {
		noun = "scope"
	}
	fmt.Fprintf(&b, "--- %s: %s ---\n", noun, scope)

	read := func(ref string) (SourceResult, bool) {
		name := SourceName(ref)
		got, err := src.Read(name, scope)
		if err != nil {
			notes = append(notes, fmt.Sprintf("%s: could not be read (%v)", name, err))
			return SourceResult{}, false
		}
		if !got.Available {
			notes = append(notes, fmt.Sprintf("%s: not available on this platform", name))
			return SourceResult{}, false
		}
		if got.Note != "" {
			notes = append(notes, fmt.Sprintf("%s: %s", name, got.Note))
		}
		return got, true
	}

	for _, cs := range t.Evidence.CmdSources {
		got, ok := read(cs.File)
		if !ok {
			// Say so in the state itself. A silently missing section reads as a
			// confident negative to whatever consumes it.
			fmt.Fprintf(&b, "\n## %s\n(not available on this platform — this is not evidence of absence)\n", label(cs))
			continue
		}
		body := got.Text
		if !got.PreScoped {
			var err error
			if body, err = scopeCmdSource(got.Text, cs, scope); err != nil {
				notes = append(notes, fmt.Sprintf("%s: %v", cs.File, err))
				continue
			}
		}
		fmt.Fprintf(&b, "\n## %s\n", label(cs))
		if got.Note != "" {
			fmt.Fprintf(&b, "(%s)\n", got.Note)
		}
		if strings.TrimSpace(body) == "" {
			b.WriteString("(empty)\n")
		} else {
			b.WriteString(strings.TrimRight(body, "\n"))
			b.WriteString("\n")
		}
	}

	for _, ls := range t.Evidence.LogSources {
		got, ok := read(ls.File)
		if !ok {
			fmt.Fprintf(&b, "\n## %s\n(not available on this platform — this is not evidence of absence)\n", ls.Label)
			continue
		}
		events, err := LogEvents(got.Text, ls, scope, t.Evidence.MaxLogEvents)
		if err != nil {
			notes = append(notes, fmt.Sprintf("%s: %v", ls.File, err))
			continue
		}
		fmt.Fprintf(&b, "\n## %s\n", ls.Label)
		if got.Note != "" {
			fmt.Fprintf(&b, "(%s)\n", got.Note)
		}
		if len(events) == 0 {
			b.WriteString("(no matching events)\n")
		}
		for _, e := range events {
			if e.Count > 1 {
				fmt.Fprintf(&b, "%s  %s  (x%d)\n", e.First, e.Template, e.Count)
			} else {
				fmt.Fprintf(&b, "%s  %s\n", e.First, e.Template)
			}
		}
	}

	out := b.String()
	if max := t.Evidence.MaxStateChars; max > 0 && len(out) > max {
		// Truncate on a line boundary and say so, rather than cutting a record
		// in half and leaving it looking like real but malformed evidence.
		cut := out[:max]
		if i := strings.LastIndexByte(cut, '\n'); i > 0 {
			cut = cut[:i]
		}
		out = cut + "\n\n[evidence truncated to fit the state budget]\n"
		notes = append(notes, fmt.Sprintf("state truncated to %d characters", max))
	}
	return out, notes, nil
}

func label(cs CmdSource) string {
	if cs.Label != "" {
		return cs.Label
	}
	return cs.File
}

// scopeCmdSource narrows one command's output per its declaration.
func scopeCmdSource(text string, cs CmdSource, scope string) (string, error) {
	switch cs.Scope {
	case "block":
		if cs.BlockHeaderRegex == "" {
			return text, nil
		}
		re, err := regexp.Compile(cs.BlockHeaderRegex)
		if err != nil {
			return "", fmt.Errorf("block_header_regex: %w", err)
		}
		blocks, _, preamble := SplitBlocks(text, re)
		var out []string
		if cs.IncludePreamble {
			out = append(out, preamble...)
		}
		if lines, ok := blocks[scope]; ok {
			out = append(out, lines...)
		} else {
			// Name the miss. "No block for this scope" and "the block was empty"
			// are different findings and must not look alike.
			out = append(out, fmt.Sprintf("(no block matching %q in this output)", scope))
		}
		return strings.Join(out, "\n"), nil

	case "grep":
		if cs.GrepRegex == "" {
			return text, nil
		}
		re, err := regexp.Compile(cs.GrepRegex)
		if err != nil {
			return "", fmt.Errorf("grep_regex: %w", err)
		}
		var out []string
		for _, line := range strings.Split(strings.ReplaceAll(text, "\r", ""), "\n") {
			if re.MatchString(line) {
				out = append(out, line)
			}
		}
		return strings.Join(out, "\n"), nil

	default: // "none", "all", ""
		return text, nil
	}
}
