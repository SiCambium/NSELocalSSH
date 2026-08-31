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

// blockOpeners lists every context-opening line documented in
// NSE3000-CLI-REFERENCE.md. A line matching one of these (after whitespace
// normalization) starts a nested Block instead of being treated as a leaf.
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
// The device's own `show config` renderer is inconsistent about how a
// block's end is marked: interface/pool/vlan-style blocks are closed only
// by the next "!" separator with no explicit "exit" line, while blocks
// entered by a bare keyword (vpn-server, dns-filter policy N, filter
// precedence N) usually show an explicit "exit" before the next "!". Both
// are handled uniformly here: "exit" pops exactly one level, and "!"
// resets the whole stack back to the root regardless of current depth.
// Blank lines are ignored.
//
// One block type is worse than inconsistent about its closing marker: it
// has none at all. "ip group N" (confirmed by live capture) ends with
// neither "!" nor "exit" — just a blank line before the next top-level
// entry. Without a fallback, an open-but-never-closed "ip group" block
// would silently swallow everything after it (hostname, timezone, every
// section that follows) as its own children. The fallback: a line with no
// leading whitespace is always top-level content, so it forces the stack
// back to root before being processed, regardless of what's still nominally
// open — "!" and "exit" are exempted since they already have their own
// (narrower) popping logic above.
func ParseBlockTree(raw string) *Block {
	lines := linesOf(raw, "show config")
	root := &Block{}
	stack := []*Block{root}
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && trimmed != "!" && trimmed != "exit" {
			stack = stack[:1]
		}
		top := stack[len(stack)-1]
		switch {
		case trimmed == "!":
			stack = stack[:1]
		case trimmed == "exit":
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
		case isBlockOpener(normalizeSpaces(trimmed)):
			b := &Block{Header: normalizeSpaces(trimmed)}
			top.Children = append(top.Children, Node{Block: b})
			stack = append(stack, b)
		default:
			top.Children = append(top.Children, Node{Line: trimmed})
		}
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
