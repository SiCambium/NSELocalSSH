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
	flag.Parse()
	if *showVersion {
		fmt.Printf("nse-status %s\n", nse.BuildVersion)
		os.Exit(0)
	}

	cfg := nse.LoadConfig()
	if cfg.Password == "" {
		log.Printf("NSE_PASSWORD is not set yet; open Settings to add it")
	}
	client := nse.NewClient(cfg)
	defer client.Close()

	srv := &nse.Server{Client: client, Static: web.Static, SettingsPath: nse.WritableSettingsPath()}
	log.Printf("NSE status %s on http://%s (device %s)", nse.BuildVersion, cfg.Listen, cfg.Addr())
	if err := http.ListenAndServe(cfg.Listen, srv.Handler()); err != nil {
		log.Fatal(err)
	}
}
