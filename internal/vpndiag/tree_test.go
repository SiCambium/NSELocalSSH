package vpndiag

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
)

func loadShipped(t *testing.T, docID string) *Tree {
	t.Helper()
	tree, err := LoadFS(Playbooks(), docID)
	if err != nil {
		t.Fatalf("loading %s: %v", docID, err)
	}
	return tree
}

// TestShippedPlaybooksValidate guards the data. Load() validates, so a retuned
// tree with a dangling branch or a missing candidate fails here rather than at
// the first diagnosis a user runs.
func TestShippedPlaybooksValidate(t *testing.T) {
	for _, doc := range []string{DocS2S, DocWireGuard} {
		tree := loadShipped(t, doc)
		if tree.DocID != doc {
			t.Errorf("%s: doc_id = %q", doc, tree.DocID)
		}
		if len(tree.Nodes) == 0 || len(tree.Leaves) == 0 || len(tree.Candidates) == 0 {
			t.Errorf("%s: empty tree", doc)
		}
		// Every node must be answerable as a question.
		for id, q := range tree.Questions() {
			if q.Instructions == "" || len(q.Criteria) == 0 {
				t.Errorf("%s: node %q produced an unusable question", doc, id)
			}
		}
	}
}

// TestFixAcceptsBothShapes is the reason FlexStrings exists: `candidate.fix` is
// an ARRAY in the s2s playbook and a STRING in the wireguard one. Python does
// not care; Go would fail to unmarshal one of the two with either concrete type,
// so both shipped files are loaded and their fix fields read.
func TestFixAcceptsBothShapes(t *testing.T) {
	s2s := loadShipped(t, DocS2S)
	wg := loadShipped(t, DocWireGuard)

	countWithFix := func(tr *Tree) int {
		n := 0
		for _, c := range tr.Candidates {
			if len(c.Fix) > 0 {
				n++
			}
		}
		return n
	}
	if countWithFix(s2s) == 0 {
		t.Error("no s2s candidate had a fix — the array form failed to decode")
	}
	if countWithFix(wg) == 0 {
		t.Error("no wireguard candidate had a fix — the string form failed to decode")
	}

	// And directly, so the failure message is unambiguous.
	var probe struct {
		Fix FlexStrings `json:"fix"`
	}
	if err := json.Unmarshal([]byte(`{"fix":"a single string"}`), &probe); err != nil {
		t.Fatalf("string form: %v", err)
	}
	if len(probe.Fix) != 1 || probe.Fix[0] != "a single string" {
		t.Errorf("string form decoded to %q", probe.Fix)
	}
	if err := json.Unmarshal([]byte(`{"fix":["one","two"]}`), &probe); err != nil {
		t.Fatalf("array form: %v", err)
	}
	if len(probe.Fix) != 2 {
		t.Errorf("array form decoded to %q", probe.Fix)
	}
	if err := json.Unmarshal([]byte(`{"fix":null}`), &probe); err != nil || probe.Fix != nil {
		t.Errorf("null should decode to nil, got %q err %v", probe.Fix, err)
	}
	if err := json.Unmarshal([]byte(`{"fix":42}`), &probe); err == nil {
		t.Error("a number should be rejected rather than silently dropped")
	}
}

// TestPlaybooksMatchUpstream guards against the embedded copies drifting from
// the handoff reference, which is shared with a Python implementation. Skipped
// when the reference is not on disk (it is not needed to build or ship).
func TestPlaybooksMatchUpstream(t *testing.T) {
	for _, doc := range []string{DocS2S, DocWireGuard} {
		up := filepath.Join("..", "..", "jev-vpn-debug-onbox", "playbooks", doc+".tree.json")
		want, err := os.ReadFile(up)
		if err != nil {
			t.Skipf("upstream reference not present: %v", err)
		}
		got, err := os.ReadFile(filepath.Join("playbooks", doc+".tree.json"))
		if err != nil {
			t.Fatalf("reading embedded copy: %v", err)
		}
		if string(got) != string(want) {
			t.Errorf("%s has diverged from jev-vpn-debug-onbox/playbooks/ — the tree is shared "+
				"with an upstream implementation, so device-specific changes belong in the "+
				"EvidenceSource, not in the data", doc)
		}
	}
}

func noul(v float64) Answer { return Answer{Type: "noul", Noul: &v} }

// walkTree is a tiny hand-built tree so the traversal is testable independently
// of the shipped playbooks.
func walkTree() *Tree {
	return &Tree{
		Root: "a",
		Nodes: map[string]Node{
			"a": {Instructions: "a?", Criteria: map[string]string{"true": "t"}, Yes: "b", No: "leaf_no"},
			"b": {Instructions: "b?", Criteria: map[string]string{"true": "t"}, Yes: "leaf_yes", No: "leaf_esc"},
		},
		Leaves: map[string]Leaf{
			"leaf_yes": {Candidate: "C1"},
			"leaf_no":  {Candidate: "C2"},
			"leaf_esc": {Escalate: true, Note: "nothing conclusive"},
		},
		Candidates: map[string]Candidate{
			"C1": {ID: "C1", Title: "first", Fix: FlexStrings{"do the thing"}},
			"C2": {ID: "C2", Title: "second"},
		},
		Defers: map[string]string{"C2": "another-playbook"},
	}
}

func TestWalkBranchesAndLands(t *testing.T) {
	tr := walkTree()
	res, err := tr.Walk(map[string]Answer{"a": noul(0.9), "b": noul(0.95)})
	if err != nil {
		t.Fatal(err)
	}
	if res.Leaf != "leaf_yes" || res.CandidateID != "C1" {
		t.Fatalf("landed on %q / %q", res.Leaf, res.CandidateID)
	}
	if res.Candidate == nil || res.Candidate.Title != "first" {
		t.Errorf("candidate not attached: %+v", res.Candidate)
	}
	if len(res.Path) != 2 || res.Path[0].Branch != "yes" || res.Path[1].Branch != "yes" {
		t.Errorf("path = %+v", res.Path)
	}
	if res.Escalate {
		t.Error("two confident answers must not escalate")
	}
	// min |noul - 0.5| along the path: |0.9-0.5| = 0.4, |0.95-0.5| = 0.45.
	if res.MinConfidence == nil || math.Abs(*res.MinConfidence-0.4) > 1e-9 {
		t.Errorf("min confidence = %v, want 0.4", res.MinConfidence)
	}
	// AllNouls covers every node, not just the path.
	if len(res.AllNouls) != len(tr.Nodes) {
		t.Errorf("all_nouls has %d entries, want %d", len(res.AllNouls), len(tr.Nodes))
	}
}

// TestWalkNilNoulEscalates is the pointer-vs-value trap. An unanswered node
// takes the "no" branch, which a float64 zero-value would also do — but it must
// ALSO set escalate. Collapsing the two makes the walk claim confidence it does
// not have.
func TestWalkNilNoulEscalates(t *testing.T) {
	tr := walkTree()
	res, err := tr.Walk(map[string]Answer{"a": {Type: "noul"}}) // no answer at all
	if err != nil {
		t.Fatal(err)
	}
	if res.Leaf != "leaf_no" {
		t.Errorf("an unanswered node should take the no branch, landed %q", res.Leaf)
	}
	if !res.Escalate {
		t.Error("an unanswered node must set escalate — this is the whole reason Noul is a pointer")
	}
	if res.Path[0].Noul != nil {
		t.Error("the path must record that the node was unanswered")
	}

	// Contrast: an explicit 0.0 takes the same branch but is a CONFIDENT no.
	res2, err := tr.Walk(map[string]Answer{"a": noul(0.0)})
	if err != nil {
		t.Fatal(err)
	}
	if res2.Leaf != "leaf_no" {
		t.Errorf("0.0 should take the no branch, landed %q", res2.Leaf)
	}
	if res2.Escalate {
		t.Error("a confident 0.0 must NOT escalate — that is the distinction a float64 would lose")
	}
}

// TestWalkNearCoinFlipEscalates covers the margin: a branch is still taken, but
// the walk is flagged.
func TestWalkNearCoinFlipEscalates(t *testing.T) {
	tr := walkTree()
	res, err := tr.Walk(map[string]Answer{"a": noul(0.53), "b": noul(0.99)})
	if err != nil {
		t.Fatal(err)
	}
	if res.Leaf != "leaf_yes" {
		t.Errorf("0.53 >= threshold so it should still branch yes, landed %q", res.Leaf)
	}
	if !res.Escalate {
		t.Errorf("|0.53-0.5| = 0.03 is inside the %v margin and must escalate", Margin)
	}
	if res.Reason == "" {
		t.Error("an escalating walk should say why")
	}

	// Exactly at the threshold branches yes, and is inside the margin.
	res, err = tr.Walk(map[string]Answer{"a": noul(Threshold), "b": noul(0.99)})
	if err != nil {
		t.Fatal(err)
	}
	if res.Path[0].Branch != "yes" {
		t.Error("noul == threshold must branch yes (>=, not >)")
	}
	if !res.Escalate {
		t.Error("noul exactly at the threshold is a coin flip and must escalate")
	}
}

func TestWalkEscalateLeafAndDefer(t *testing.T) {
	tr := walkTree()
	res, err := tr.Walk(map[string]Answer{"a": noul(0.9), "b": noul(0.01)})
	if err != nil {
		t.Fatal(err)
	}
	if res.Leaf != "leaf_esc" || res.CandidateID != "" {
		t.Fatalf("landed %q candidate %q", res.Leaf, res.CandidateID)
	}
	if !res.Escalate || res.Note != "nothing conclusive" {
		t.Errorf("escalate=%v note=%q", res.Escalate, res.Note)
	}

	// A candidate with a declared defer target reports it. In the shipped s2s
	// tree two candidates defer to a playbook that is not part of the handoff,
	// so callers must cope with a target they cannot load.
	res, err = tr.Walk(map[string]Answer{"a": noul(0.1)})
	if err != nil {
		t.Fatal(err)
	}
	if res.CandidateID != "C2" || res.DeferTo != "another-playbook" {
		t.Errorf("candidate %q defer %q", res.CandidateID, res.DeferTo)
	}
}

// TestWalkCycleErrors covers the guard SPEC.md's pseudocode omits. Without
// MaxSteps a malformed playbook hangs instead of failing.
func TestWalkCycleErrors(t *testing.T) {
	tr := &Tree{
		Root: "a",
		Nodes: map[string]Node{
			"a": {Instructions: "a?", Criteria: map[string]string{"true": "t"}, Yes: "b", No: "b"},
			"b": {Instructions: "b?", Criteria: map[string]string{"true": "t"}, Yes: "a", No: "a"},
		},
		Leaves:     map[string]Leaf{"unreachable": {}},
		Candidates: map[string]Candidate{"C": {ID: "C"}},
	}
	if _, err := tr.Walk(map[string]Answer{"a": noul(0.9), "b": noul(0.9)}); err == nil {
		t.Fatal("a cyclic tree must error, not spin")
	}
}

func TestValidateRejectsBadTrees(t *testing.T) {
	base := func() *Tree { return walkTree() }

	for _, tc := range []struct {
		name string
		mut  func(*Tree)
	}{
		{"root is not a node", func(tr *Tree) { tr.Root = "leaf_yes" }},
		{"dangling yes target", func(tr *Tree) {
			n := tr.Nodes["a"]
			n.Yes = "nowhere"
			tr.Nodes["a"] = n
		}},
		{"node with no instructions", func(tr *Tree) {
			n := tr.Nodes["a"]
			n.Instructions = "  "
			tr.Nodes["a"] = n
		}},
		{"node with no criteria", func(tr *Tree) {
			n := tr.Nodes["a"]
			n.Criteria = nil
			tr.Nodes["a"] = n
		}},
		{"leaf references a missing candidate", func(tr *Tree) {
			tr.Leaves["leaf_yes"] = Leaf{Candidate: "NOPE"}
		}},
	} {
		tr := base()
		tc.mut(tr)
		if err := tr.Validate(); err == nil {
			t.Errorf("%s: Validate() accepted it", tc.name)
		}
	}

	if err := base().Validate(); err != nil {
		t.Errorf("the good tree was rejected: %v", err)
	}
}

// TestWalkReportsConfidenceBand covers the label shown instead of a
// probability. The numbers are calibrated but invite false precision, so an
// operator gets low/medium/high; the bands live with the walk so every consumer
// labels the same walk identically.
func TestWalkReportsConfidenceBand(t *testing.T) {
	tr := walkTree()
	for _, tc := range []struct {
		name    string
		answers map[string]Answer
		want    string
		why     string
	}{
		{"decisive both steps", map[string]Answer{"a": noul(0.97), "b": noul(0.99)}, ConfidenceHigh,
			"closest call 0.47 from the threshold"},
		{"one middling step", map[string]Answer{"a": noul(0.75), "b": noul(0.99)}, ConfidenceMedium,
			"closest call 0.25 — past the margin but short of high"},
		{"near coin flip", map[string]Answer{"a": noul(0.52), "b": noul(0.99)}, ConfidenceLow,
			"closest call 0.02 is inside the margin"},
		{"exactly at the high edge", map[string]Answer{"a": noul(0.80), "b": noul(0.99)}, ConfidenceHigh,
			"0.30 is inclusive"},
		{"unanswered node", map[string]Answer{"b": noul(0.99)}, ConfidenceLow,
			"a node Jev did not answer is doubt of a different kind, same advice"},
	} {
		res, err := tr.Walk(tc.answers)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if res.Confidence != tc.want {
			t.Errorf("%s: confidence = %q, want %q (%s; min_confidence=%v escalate=%v)",
				tc.name, res.Confidence, tc.want, tc.why, res.MinConfidence, res.Escalate)
		}
	}
}

// TestEscalateLeafIsAlwaysLowConfidence pins the precedence: a leaf that
// declares itself inconclusive is low confidence however decisive the steps
// that reached it looked.
func TestEscalateLeafIsAlwaysLowConfidence(t *testing.T) {
	tr := walkTree()
	res, err := tr.Walk(map[string]Answer{"a": noul(0.99), "b": noul(0.01)})
	if err != nil {
		t.Fatal(err)
	}
	if res.Leaf != "leaf_esc" {
		t.Fatalf("landed %q, want the escalate leaf", res.Leaf)
	}
	if res.Confidence != ConfidenceLow {
		t.Errorf("confidence = %q, want low — the leaf declares itself inconclusive", res.Confidence)
	}
}
