package nse

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Demo mode replays recorded device captures instead of dialing a device,
// so the UI can be developed, reviewed and demonstrated without hardware
// in front of you. It is read-only by construction: a command with no
// recorded output fails the same way an unknown command does, which means
// every config write fails too. Nothing here ever opens an SSH connection.
//
// The captures in testdata/ all begin with the command that produced them
// — that is how the device echoes back what you typed — so the index is
// built from the files themselves rather than a hand-maintained table
// that would drift the moment someone adds a capture. Where several
// captures share a command (four files start with "show config"), the
// largest wins: it is the most complete recording of that command.
func (c *Client) LoadReplay(dir string) error {
	paths, err := filepath.Glob(filepath.Join(dir, "*.txt"))
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return fmt.Errorf("no .txt captures found in %s", dir)
	}

	replay := map[string]string{}
	size := map[string]int64{}
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		first, _, _ := strings.Cut(string(data), "\n")
		command := strings.TrimSpace(first)
		if command == "" {
			continue
		}
		if existing, ok := size[command]; ok && existing >= info.Size() {
			continue
		}
		size[command] = info.Size()
		replay[command] = string(data)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.replay = replay
	return nil
}

// ReplayCommands lists the commands demo mode can answer, sorted, so the
// startup log can say what the UI will and will not be able to show.
func (c *Client) ReplayCommands() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	cmds := make([]string, 0, len(c.replay))
	for cmd := range c.replay {
		cmds = append(cmds, cmd)
	}
	sort.Strings(cmds)
	return cmds
}
