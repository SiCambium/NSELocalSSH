package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"nse-cli/internal/nse"
)

func main() {
	cfg := nse.LoadConfig()
	c := nse.NewClient(cfg)
	defer c.Close()
	for _, cmd := range []string{"service show ifconfig", "service show top"} {
		out, err := c.Run(cmd, 20*time.Second)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s ERR %v\n", cmd, err)
		}
		text := strings.ReplaceAll(out, "\r", "")
		name := strings.ReplaceAll(cmd, " ", "_")
		path := "internal/nse/testdata/probe_" + name + ".txt"
		_ = os.WriteFile(path, []byte(text), 0o644)
		fmt.Fprintf(os.Stderr, "wrote %s %d bytes\n", path, len(text))
	}
}
