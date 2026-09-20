package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

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
	journal := nse.NewConfigJournal(nse.JournalPath(settingsPath))

	srv := &nse.Server{
		Client:       client,
		Static:       web.Static,
		SettingsPath: settingsPath,
		History:      history,
		Journal:      journal,
	}
	// The history store flushes on a timer, so at most a minute of
	// samples is ever only in memory — but only if something gets the
	// chance to write it, and until now nothing did. A deferred
	// history.Flush() here never ran: ListenAndServe blocks until it
	// fails and log.Fatal then exits without unwinding a single deferred
	// call, while an unhandled Ctrl-C terminates the process outright.
	//
	// So the signal is caught, the listener is closed, and the flush
	// happens on the way out. A second signal is deliberately left
	// unhandled: someone pressing Ctrl-C twice wants out now, not a
	// tidier shutdown.
	httpSrv := &http.Server{Addr: cfg.Listen, Handler: srv.Handler()}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		log.Printf("NSE status %s on http://%s (device %s)", nse.BuildVersion, cfg.Listen, cfg.Addr())
		errCh <- httpSrv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		// The listener failed on its own, a port already in use being the
		// usual cause. Flush anyway: samples may already have been taken.
		history.Flush()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	case sig := <-stop:
		log.Printf("%s received, saving history and shutting down", sig)
		signal.Stop(stop)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := httpSrv.Shutdown(ctx); err != nil {
			log.Printf("shutdown: %v", err)
		}
		history.Flush()
	}
}
