package main

import (
	"log"
	"net/http"

	"nse-cli/internal/nse"
	"nse-cli/web"
)

func main() {
	cfg := nse.LoadConfig()
	if cfg.Password == "" {
		log.Printf("NSE_PASSWORD is not set yet; open Settings to add it")
	}
	client := nse.NewClient(cfg)
	defer client.Close()

	srv := &nse.Server{Client: client, Static: web.Static, SettingsPath: nse.WritableSettingsPath()}
	log.Printf("NSE status GUI on http://%s (device %s)", cfg.Listen, cfg.Addr())
	if err := http.ListenAndServe(cfg.Listen, srv.Handler()); err != nil {
		log.Fatal(err)
	}
}
