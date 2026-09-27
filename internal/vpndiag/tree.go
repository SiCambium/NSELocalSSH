// Package vpndiag walks a VPN troubleshooting playbook against evidence
// gathered from a device.
//
// The playbook JSON in playbooks/ is the asset; this package is an interpreter
// of it. Those files are shared with an upstream Python implementation and must
// stay byte-identical — anything environment-specific (which command supplies
// which logical evidence source) belongs in the EvidenceSource implementation,
// not in the data.
//
// Behaviour here is ported from that Python reference. Where its SPEC.md and
// its code disagreed, the code won; the divergences that mattered are noted at
// the functions concerned.
//
// This package deliberately has no dependency on the device packages and never
// reads a credential from the environment: the tree walk and evidence assembly
// are pure logic over data, so they stay testable with no device and no egress.
package vpndiag

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"sort"
	"strings"
)

// Walk tuning, matching the Python reference's defaults.
const (
	// Threshold above which a noul is read as "yes".
	Threshold = 0.5

	// Margin within which a noul is treated as too close to call. A node this
	// near the threshold flags the whole walk for escalation even though it
	// still picks a branch.
	Margin = 0.10

	// MaxSteps guards against a cyclic tree. The Python reference has this and
	// SPEC.md's pseudocode omits it; without it a malformed playbook hangs.
	MaxSteps = 64
)

// FlexStrings accepts either a JSON string or an array of strings.
//
// This is not defensiveness for its own sake: `candidate.fix` is an array in
// s2s-vpn-troubleshooting and a bare string in wireguard-vpn-troubleshooting.
// Python does not care; Go would fail to unmarshal one of the two shipped
// playbooks with either concrete type.
type FlexStrings []string

func (f *FlexStrings) UnmarshalJSON(b []byte) error {
	trimmed := strings.TrimSpace(string(b))
	if trimmed == "null" {
		*f = nil
		return nil
	}
	if strings.HasPrefix(trimmed, "[") {
		var list []string
		if err := json.Unmarshal(b, &list); err != nil {
			return err
		}
		*f = list
		return nil
	}
	var one string
	if err := json.Unmarshal(b, &one); err != nil {
		return fmt.Errorf("expected a string or an array of strings, got %s", trimmed)
	}
	if one == "" {
		*f = nil
		return nil
	}
	*f = []string{one}
	return nil
}

// Node is a binary decision point. Every node is a "noul" question: Jev returns
// P(criteria.true) and the walk branches on it.
type Node struct {
	Type         string            `json:"type"`
	Instructions string            `json:"instructions"`
	Criteria     map[string]string `json:"criteria"`
	Yes          string            `json:"yes"`
	No           string            `json:"no"`
}

// Leaf ends a walk. Candidate may be empty, which means "no confident cause" —
// those leaves carry Escalate and a Note instead.
type Leaf struct {
	Candidate string `json:"candidate"`
	Escalate  bool   `json:"escalate"`
	Note      string `json:"note"`
}

// Candidate is a diagnosis.
//
// Confirm, RuleOut, EvidenceSources and Partial are present in the s2s playbook
// but undocumented in SPEC.md's schema table. Confirm and RuleOut are how an
// operator verifies a verdict, so they are modelled and meant to be displayed.
type Candidate struct {
	ID              string      `json:"id"`
	Title           string      `json:"title"`
	Mechanism       string      `json:"mechanism"`
	Fix             FlexStrings `json:"fix"`
	Confirm         FlexStrings `json:"confirm"`
	RuleOut         FlexStrings `json:"rule_out"`
	EvidenceSources FlexStrings `json:"evidence_sources"`
	Partial         bool        `json:"partial"`
}

// Tree is a whole playbook.
type Tree struct {
	DocID      string               `json:"doc_id"`
	Title      string               `json:"title"`
	Root       string               `json:"root"`
	Evidence   Evidence             `json:"evidence"`
	Nodes      map[string]Node      `json:"nodes"`
	Leaves     map[string]Leaf      `json:"leaves"`
	Candidates map[string]Candidate `json:"candidates"`

	// Defers maps a candidate to another playbook that covers it in depth. In
	// the shipped s2s tree two candidates defer to a playbook that is not part
	// of the handoff, so a caller must handle a target it cannot load.
	Defers map[string]string `json:"defers"`
}

// Load parses and validates a playbook.
func Load(data []byte) (*Tree, error) {
	var t Tree
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("parsing playbook: %w", err)
	}
	if err := t.Validate(); err != nil {
		return nil, err
	}
	return &t, nil
}

// LoadFS reads a playbook by doc id from a filesystem laid out as
// "<docID>.tree.json".
func LoadFS(fsys fs.FS, docID string) (*Tree, error) {
	name := docID + ".tree.json"
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		return nil, fmt.Errorf("reading playbook %s: %w", name, err)
	}
	return Load(data)
}

// Validate checks the structure a walk depends on: the root exists, every
// branch resolves, every node can be turned into a question, and every
// candidate reference is real. Checked in that order, matching the reference.
func (t *Tree) Validate() error {
	if t.Root == "" || len(t.Nodes) == 0 || len(t.Leaves) == 0 || len(t.Candidates) == 0 {
		return errors.New("playbook missing root, nodes, leaves or candidates")
	}
	if _, ok := t.Nodes[t.Root]; !ok {
		return fmt.Errorf("root %q is not a node", t.Root)
	}
	// Sorted so the first error reported is stable across runs rather than
	// depending on Go's randomised map order.
	for _, id := range sortedKeys(t.Nodes) {
		n := t.Nodes[id]
		for branch, target := range map[string]string{"yes": n.Yes, "no": n.No} {
			if _, ok := t.Nodes[target]; ok {
				continue
			}
			if _, ok := t.Leaves[target]; ok {
				continue
			}
			return fmt.Errorf("node %q %s->%q resolves to nothing", id, branch, target)
		}
		if strings.TrimSpace(n.Instructions) == "" || len(n.Criteria) == 0 {
			return fmt.Errorf("node %q missing instructions or criteria", id)
		}
	}
	for _, id := range sortedKeys(t.Leaves) {
		if cid := t.Leaves[id].Candidate; cid != "" {
			if _, ok := t.Candidates[cid]; !ok {
				return fmt.Errorf("leaf %q references unknown candidate %q", id, cid)
			}
		}
	}
	return nil
}

// Questions builds one noul question per node, keyed by node id — the payload
// for a single batched Decide call.
func (t *Tree) Questions() map[string]Question {
	out := make(map[string]Question, len(t.Nodes))
	for id, n := range t.Nodes {
		out[id] = Question{Type: "noul", Instructions: n.Instructions, Criteria: n.Criteria}
	}
	return out
}

// Step is one node visited by a walk.
type Step struct {
	Node         string   `json:"node"`
	Instructions string   `json:"instructions"`
	Noul         *float64 `json:"noul"`
	Branch       string   `json:"branch"`
}

// Result is the outcome of a walk.
type Result struct {
	Path   []Step `json:"path"`
	Leaf   string `json:"leaf"`
	Note   string `json:"note,omitempty"`
	Reason string `json:"reason,omitempty"`

	CandidateID string     `json:"candidate_id,omitempty"`
	Candidate   *Candidate `json:"candidate,omitempty"`

	// DeferTo names another playbook covering this candidate in depth, when the
	// tree declares one. It may not be a playbook that exists here.
	DeferTo string `json:"defer_to,omitempty"`

	// Escalate is set when the leaf says so, or when any node on the path was
	// within Margin of the threshold. It means "low confidence — verify
	// independently", not "the diagnosis is wrong".
	Escalate bool `json:"escalate"`

	// MinConfidence is the smallest distance from the threshold along the path:
	// how close the least certain decision came to a coin flip. Nil when no
	// node was visited.
	MinConfidence *float64 `json:"min_confidence,omitempty"`

	// AllNouls carries every node's probability, not just those on the path —
	// the "we checked every branch" view. The Python reference returns this and
	// SPEC.md's documented return shape omits it.
	AllNouls map[string]*float64 `json:"all_nouls"`
}

// Walk traverses the tree using pre-computed answers.
//
// Answers are supplied rather than fetched so the traversal stays testable with
// no network. Jev's questions are non-conditional — every node is evaluated
// against one state — so a caller makes exactly one Decide call for all of them
// and passes the result here.
func (t *Tree) Walk(answers map[string]Answer) (*Result, error) {
	res := &Result{
		Path:     []Step{},
		AllNouls: make(map[string]*float64, len(t.Nodes)),
	}
	// Every node, answered or not — an unanswered node is a meaningful absence.
	for id := range t.Nodes {
		res.AllNouls[id] = answers[id].Noul
	}

	minConf := math.Inf(1)
	lowConf := false
	cur := t.Root

	for steps := 0; steps < MaxSteps; steps++ {
		n, isNode := t.Nodes[cur]
		if !isNode {
			break
		}
		noul := answers[cur].Noul
		branch := "no"
		if noul == nil {
			// Unanswered: cannot branch confidently. Taking "no" matches the
			// reference, but the low-confidence flag is the point — a plain
			// float64 zero here would take the same branch while silently
			// claiming certainty.
			lowConf = true
		} else {
			if *noul >= Threshold {
				branch = "yes"
			}
			if dist := math.Abs(*noul - Threshold); dist < minConf {
				minConf = dist
			}
			if math.Abs(*noul-Threshold) < Margin {
				lowConf = true
			}
		}
		res.Path = append(res.Path, Step{
			Node: cur, Instructions: n.Instructions, Noul: noul, Branch: branch,
		})
		if branch == "yes" {
			cur = n.Yes
		} else {
			cur = n.No
		}
	}

	leaf, ok := t.Leaves[cur]
	if !ok {
		// Either a cycle or a branch into nothing. Validate() rules the latter
		// out at load, so this is the cycle guard firing.
		return nil, fmt.Errorf("walk did not reach a leaf after %d steps (stopped at %q)", MaxSteps, cur)
	}

	res.Leaf = cur
	res.Note = leaf.Note
	res.Escalate = leaf.Escalate || lowConf
	if len(res.Path) > 0 && !math.IsInf(minConf, 1) {
		rounded := math.Round(minConf*10000) / 10000
		res.MinConfidence = &rounded
	}
	if leaf.Candidate != "" {
		res.CandidateID = leaf.Candidate
		if c, ok := t.Candidates[leaf.Candidate]; ok {
			res.Candidate = &c
		}
		if d, ok := t.Defers[leaf.Candidate]; ok {
			res.DeferTo = d
		}
	}
	switch {
	case res.CandidateID == "":
		res.Reason = "no candidate cause was reached; the evidence did not match a known pattern"
	case lowConf:
		res.Reason = "a decision on this path was close to a coin flip, so treat the cause as a lead rather than a finding"
	}
	return res, nil
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
