package nse

import (
	"regexp"
	"strconv"
	"strings"
)

// UserGroup, IPGroup, and AppGroup mirror the CLI's "Groups" feature
// (cnMaestro's User Groups / IP Groups / Application Groups). None of
// this is exposed via cloud-json-config or any `show` verb — it only
// renders as top-level `show config` blocks — so it's parsed from the
// block tree, unlike most other sections in this app. Syntax and index
// ranges below were confirmed by live testing against a real 2.3-r6 unit
// (materialize a group, diff `show config`, remove, diff again) plus a
// v2.1 CLI reference tree, not guessed.
type UserGroup struct {
	ID           int    `json:"id"`
	Name         string `json:"name"`
	SourceSubnet string `json:"source_subnet"`
}

type IPGroup struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"`
}

type AppGroup struct {
	ID           int      `json:"id"`
	Name         string   `json:"name"`
	Applications []string `json:"applications"`
	Categories   []string `json:"categories"`
}

type GroupsConfig struct {
	UserGroups []UserGroup `json:"user_groups"`
	IPGroups   []IPGroup   `json:"ip_groups"`
	AppGroups  []AppGroup  `json:"app_groups"`
}

var groupIDRE = regexp.MustCompile(`(\d+)$`)

func blockID(header string) int {
	m := groupIDRE.FindStringSubmatch(header)
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

// leavesWithPrefix returns every direct child leaf line of b starting with
// prefix, with the prefix stripped — unlike Block.Leaf, which only
// returns the first match. Needed for application-group's "application"
// and "category" leaves, which a real group can repeat.
func leavesWithPrefix(b *Block, prefix string) []string {
	var out []string
	for _, child := range b.Children {
		if child.Block == nil && strings.HasPrefix(child.Line, prefix) {
			out = append(out, strings.TrimSpace(strings.TrimPrefix(child.Line, prefix)))
		}
	}
	return out
}

func leafValue(b *Block, prefix string) string {
	line, ok := b.Leaf(prefix)
	if !ok {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(line, prefix))
}

// ParseGroupsConfig parses User/IP/Application groups out of a raw `show
// config` capture. "group N" (user groups), "ip group N", and
// "application-group N" are distinct top-level block headers that don't
// collide under prefix matching.
func ParseGroupsConfig(raw string) GroupsConfig {
	tree := ParseBlockTree(raw)
	var cfg GroupsConfig
	for _, blk := range tree.FindAll("group ") {
		cfg.UserGroups = append(cfg.UserGroups, UserGroup{
			ID:           blockID(blk.Header),
			Name:         leafValue(blk, "name "),
			SourceSubnet: leafValue(blk, "source-subnet "),
		})
	}
	for _, blk := range tree.FindAll("ip group ") {
		cfg.IPGroups = append(cfg.IPGroups, IPGroup{
			ID:      blockID(blk.Header),
			Name:    leafValue(blk, "name "),
			Address: leafValue(blk, "address "),
		})
	}
	for _, blk := range tree.FindAll("application-group ") {
		cfg.AppGroups = append(cfg.AppGroups, AppGroup{
			ID:           blockID(blk.Header),
			Name:         leafValue(blk, "name "),
			Applications: leavesWithPrefix(blk, "application "),
			Categories:   leavesWithPrefix(blk, "category "),
		})
	}
	return cfg
}
