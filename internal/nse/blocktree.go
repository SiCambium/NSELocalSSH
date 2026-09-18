package nse

import (
	"regexp"
	"strings"
)

// Node is either a leaf command line or a nested sub-context within a
// config tree — never both.
type Node struct {
	Line  string
	Block *Block
}

// Block is a CLI config context (a sub-mode entered by a header line such
// as "interface eth 1", or the implicit root context) containing an
// ordered sequence of leaf lines and nested sub-blocks.
type Block struct {
	Header   string
	Children []Node
}

// blockOpeners lists context-opening lines confirmed from
// NSE3000-CLI-REFERENCE.md. Matching one of these (after whitespace
// normalization) always starts a nested Block — even when the block turns
// out to be empty, which indentation alone cannot detect and which
// Find()-based callers rely on to tell "section present but empty" apart
// from "section absent". Lines outside this list can still open a block;
// see ParseBlockTree.
var blockOpeners = []*regexp.Regexp{
	regexp.MustCompile(`^interface (eth|vlan) \d+$`),
	regexp.MustCompile(`^ip dhcp pool \d+$`),
	regexp.MustCompile(`^ip dns dynamic services-list \d+$`),
	regexp.MustCompile(`^dns-server$`),
	regexp.MustCompile(`^dns-filter policy \d+$`),
	regexp.MustCompile(`^vpn-server$`),
	regexp.MustCompile(`^filter global-filter$`),
	regexp.MustCompile(`^filter precedence \d+$`),
	regexp.MustCompile(`^site-to-site-vpn$`),
	regexp.MustCompile(`^vpn ipsec \d+$`),
	regexp.MustCompile(`^ike phase [12]$`),
	regexp.MustCompile(`^radius-server client-list \d+$`),
	regexp.MustCompile(`^radius-server users-list \d+$`),
	regexp.MustCompile(`^group \d+$`),
	regexp.MustCompile(`^ip group \d+$`),
	regexp.MustCompile(`^application-group \d+$`),
}

// indentOf returns the display width of a line's leading whitespace,
// counting a tab as one column — this device indents with spaces, and the
// only thing that matters here is the relative ordering of two lines'
// indents, not their exact column.
func indentOf(line string) int {
	return len(line) - len(strings.TrimLeft(line, " \t"))
}

func normalizeSpaces(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func isBlockOpener(normalized string) bool {
	for _, re := range blockOpeners {
		if re.MatchString(normalized) {
			return true
		}
	}
	return false
}

// ParseBlockTree parses raw CLI config text (a `show config` dump, or any
// equivalent CLI text such as a free-text override block) into a tree of
// nested config contexts. It never fails: unrecognized lines become
// leaves of whatever context is currently open, and any still-open blocks
// at end of input are implicitly closed.
//
// The device's own `show config` renderer is wildly inconsistent about how
// a block ends. Some blocks ("interface eth 1", "ip dhcp pool 1") are
// closed only by the next "!". Some ("vpn-server", "dns-filter policy 1")
// print an explicit "exit". Some ("ip group 1") print neither and simply
// end at the next top-level entry. And some — "port-forward-rule 1" and
// "source-nat-rule 1", both nested inside an interface on a live
// firmware-2.3-r6 unit — end only when the next sibling at the same indent
// begins.
//
// What the renderer IS consistent about is indentation: a block's contents
// are always printed deeper than its header. So indentation, not a list of
// known keywords, is the primary signal here:
//
//   - "!" resets the stack to the root, whatever depth it was at.
//   - "exit" pops exactly one level.
//   - Any other line first pops every open block whose header is indented
//     at or deeper than the line itself, which closes implicitly-ended
//     blocks (a same-indent sibling, or a top-level line ending a nested
//     one) without needing to know their names.
//   - The line then opens a new block if it matches blockOpeners, or if
//     the next content line is indented deeper than it.
//
// Keeping blockOpeners as an additional signal matters for blocks that are
// legitimately empty, where there is no deeper line to detect.
//
// Getting this wrong is not cosmetic. ExtractStanza builds SafeApplier's
// rollback pre-image out of this tree, so an unrecognized sub-context used
// to do two damaging things at once on a real device: flatten its children
// into the parent (replaying "source-nat-rule 2" while still inside
// "source-nat-rule 1"), and — because its stray "exit" then popped the
// nearest *recognized* ancestor — silently truncate that ancestor's
// stanza, so a "vpn-server" rollback restored three leaves and dropped the
// whole wireguard sub-block.
//
// One inference is carried over from the old behavior rather than
// independently confirmed: ToLines emits an explicit "exit" after every
// nested block, including these indentation-derived ones, which assumes
// "exit" is accepted to leave any sub-context on this CLI. That is
// confirmed for the named contexts in blockOpeners and consistent with
// every context observed since; a wrong guess here is caught by
// Client.unwindLocked, which drops the shell rather than leaving it wedged.
func ParseBlockTree(raw string) *Block {
	lines := linesOf(raw, "show config")
	root := &Block{}
	stack := []*Block{root}
	// indents[i] is the display indent of stack[i]'s header. The root sits
	// at -1 so that a line at column 0 pops everything but never the root.
	indents := []int{-1}

	// nextContentIndent reports the indent of the next line that is neither
	// blank nor a "!" separator, or -1 if there is none. "exit" counts as
	// content: a context entered and left immediately ("ike-eap" followed
	// by a deeper "exit") has no children but is still a context, and
	// treating it as a leaf would let its "exit" pop the parent instead.
	nextContentIndent := func(from int) int {
		for j := from; j < len(lines); j++ {
			t := strings.TrimSpace(lines[j])
			if t == "" || t == "!" {
				continue
			}
			return indentOf(lines[j])
		}
		return -1
	}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if trimmed == "!" {
			stack, indents = stack[:1], indents[:1]
			continue
		}
		if trimmed == "exit" {
			if len(stack) > 1 {
				stack, indents = stack[:len(stack)-1], indents[:len(indents)-1]
			}
			continue
		}

		ind := indentOf(line)
		for len(stack) > 1 && ind <= indents[len(indents)-1] {
			stack, indents = stack[:len(stack)-1], indents[:len(indents)-1]
		}

		top := stack[len(stack)-1]
		normalized := normalizeSpaces(trimmed)
		if isBlockOpener(normalized) || nextContentIndent(i+1) > ind {
			b := &Block{Header: normalized}
			top.Children = append(top.Children, Node{Block: b})
			stack = append(stack, b)
			indents = append(indents, ind)
			continue
		}
		top.Children = append(top.Children, Node{Line: trimmed})
	}
	return root
}

// ToLines flattens the block into the literal CLI lines needed to
// reproduce it against a live session, including an explicit "exit" after
// every nested block — confirmed correct for driving the live CLI
// regardless of how the source `show config` dump chose to display the
// closing marker (see ParseBlockTree). The receiver's own header/closing
// exit are not included; callers wrap those themselves when needed (e.g.
// ExtractStanza).
func (b *Block) ToLines() []string {
	var out []string
	for _, child := range b.Children {
		if child.Block != nil {
			out = append(out, child.Block.Header)
			out = append(out, child.Block.ToLines()...)
			out = append(out, "exit")
		} else {
			out = append(out, child.Line)
		}
	}
	return out
}

// Serialize renders the block's contents as CLI text, one line per entry.
func (b *Block) Serialize() string {
	return strings.Join(b.ToLines(), "\n")
}

// Find returns the first direct child block whose header starts with
// headerPrefix, or nil.
func (b *Block) Find(headerPrefix string) *Block {
	for _, child := range b.Children {
		if child.Block != nil && strings.HasPrefix(child.Block.Header, headerPrefix) {
			return child.Block
		}
	}
	return nil
}

// FindAll returns every direct child block whose header starts with
// headerPrefix.
func (b *Block) FindAll(headerPrefix string) []*Block {
	var out []*Block
	for _, child := range b.Children {
		if child.Block != nil && strings.HasPrefix(child.Block.Header, headerPrefix) {
			out = append(out, child.Block)
		}
	}
	return out
}

// Leaf returns the first direct child leaf line starting with prefix.
func (b *Block) Leaf(prefix string) (string, bool) {
	for _, child := range b.Children {
		if child.Block == nil && strings.HasPrefix(child.Line, prefix) {
			return child.Line, true
		}
	}
	return "", false
}

// ExtractStanza extracts the exact lines needed to reproduce each named
// top-level entry (a block header or a bare leaf line) from raw CLI
// config text, suitable for replaying as a rollback pre-image. Each key is
// matched the same way Find/Leaf match: as a prefix of a top-level entry.
// Blocks are re-emitted via ToLines with an explicit "exit", which is
// always valid to send even if the original dump didn't show one.
func ExtractStanza(raw string, keys []string) []string {
	tree := ParseBlockTree(raw)
	var out []string
	for _, key := range keys {
		if blk := tree.Find(key); blk != nil {
			out = append(out, blk.Header)
			out = append(out, blk.ToLines()...)
			out = append(out, "exit")
			continue
		}
		if line, ok := tree.Leaf(key); ok {
			out = append(out, line)
		}
	}
	return out
}
