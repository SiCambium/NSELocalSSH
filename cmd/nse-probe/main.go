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
	cmds := []string{
		"show vpn-sessions",
		"show vpn-sessions wireguard",
		"show vpn-sessions l2tp",
		"show vpn-sessions ipsec",
		"show vpn-sessions all",
		"show vpn sessions",
		"show vpn clients",
		"show vpn status",
		"show vpn",
		"show starlink-status",
		"show starlink dish",
		"show starlink stats",
		"show starlink info",
		"show starlink status",
		"show dish",
		"show wan starlink",
		"show tailscale status",
		"show tailscale peers",
		"show ts status",
		"ping 192.168.100.1",
		"service show debug-logs tailscaled",
		"service show debug-logs vpn",
	}
	for _, cmd := range cmds {
		fmt.Fprintf(os.Stderr, "\n########## %s ##########\n", cmd)
		out, err := c.Run(cmd, 25*time.Second)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERR %v\n", err)
		}
		text := strings.ReplaceAll(out, "\r", "")
		if len(text) > 2500 {
			text = text[:2500] + "\n...[truncated]...\n"
		}
		fmt.Print(text)
		fmt.Print("\n")
	}
}
