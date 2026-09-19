package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"nse-cli/internal/nse"
	"nse-cli/web"
)

func main() {
	showVersion := flag.Bool("version", false, "print the version and exit")
	demoDir := flag.String("demo", "", "serve recorded captures from this directory instead of a device (read-only)")
	flag.Parse()
	if *showVersion {
		fmt.Printf("nse-status %s\n", nse.BuildVersion)
		os.Exit(0)
	}

	cfg := nse.LoadConfig()
	client := nse.NewClient(cfg)
	defer client.Close()

	if *demoDir != "" {
		if err := client.LoadReplay(*demoDir); err != nil {
			log.Fatalf("demo mode: %v", err)
		}
		log.Printf("demo mode: replaying %d recorded commands from %s; no device will be contacted",
			len(client.ReplayCommands()), *demoDir)
	} else if cfg.Password == "" {
		log.Printf("NSE_PASSWORD is not set yet; open Settings to add it")
	}

	settingsPath := nse.WritableSettingsPath()
	history := nse.NewHistoryStore(nse.HistoryPath(settingsPath))
	defer history.Flush()
	journal := nse.NewConfigJournal(nse.JournalPath(settingsPath))

	srv := &nse.Server{
		Client:       client,
		Static:       web.Static,
		SettingsPath: settingsPath,
		History:      history,
		Journal:      journal,
	}
	log.Printf("NSE status %s on http://%s (device %s)", nse.BuildVersion, cfg.Listen, cfg.Addr())
	if err := http.ListenAndServe(cfg.Listen, srv.Handler()); err != nil {
		log.Fatal(err)
	}
}
