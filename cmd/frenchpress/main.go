// French Press is a slow-drip honeypot for unsolicited scanner traffic.
//
// It listens on an HTTP port and, for requests matching a configurable list
// of "bad paths" (known scanner/exploit targets like /wp-admin, /.env,
// etc.), it holds the connection open and dribbles bytes at a deliberately
// glacial pace instead of ever completing the response. Anything else is
// proxied through to a real backend, if one is configured, or gets a plain
// 404.
//
// It is a tarpit, not a weapon: it costs the caller time, not your
// bandwidth, and it never sends anything malicious back. See README.md for
// intent, limitations, and deployment notes.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/milligan22963/french-press/internal/logging"
	"github.com/milligan22963/french-press/internal/paths"
	"github.com/milligan22963/french-press/internal/tarpit"
)

func main() {
	var (
		addr            = flag.String("addr", ":8080", "address to listen on")
		badPathsFile    = flag.String("bad-paths", "", "path to a YAML file of bad paths (see configs/badpaths.example.yaml); if empty, built-in defaults are used")
		backend         = flag.String("backend", "", "URL of a real backend to proxy non-bad-path requests to (e.g. http://127.0.0.1:3000); if empty, non-bad-path requests get a plain 404")
		minDelay        = flag.Duration("min-delay", 500*time.Millisecond, "minimum delay between drip bytes")
		maxDelay        = flag.Duration("max-delay", 2*time.Second, "maximum delay between drip bytes")
		maxBrewTime     = flag.Duration("max-brew-time", 10*time.Minute, "hard cap on how long a single connection is held open")
		maxConcurrent   = flag.Int("max-concurrent", 500, "maximum number of connections brewing at once; protects your own resources under a scan flood")
		logConfig       = flag.String("log-config", "", "path to a pflog YAML file (see configs/log.example.yaml); if empty, logs text to stdout at Information")
		includeDefaults = flag.Bool("include-defaults", true, "include French Press's built-in bad-path list alongside any -bad-paths file (overrides the file's include_defaults setting if explicitly passed)")
	)
	flag.Parse()

	log, err := logging.Load(*logConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "french press: log config: %v\n", err)
		os.Exit(1)
	}
	// SIGUSR1 dumps the backlog, so a quiet-but-healthy tarpit can be told
	// apart from a wedged one without waiting for an Error.
	defer log.EnableSignalDump(syscall.SIGUSR1)()

	// Detect whether -include-defaults was explicitly passed, so it can
	// override the YAML file's include_defaults setting only when the
	// user actually asked it to.
	flagSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "include-defaults" {
			flagSet = true
		}
	})

	badPathList, err := paths.Load(*badPathsFile, *includeDefaults, flagSet)
	if err != nil {
		log.Fatalf("french press: %v", err)
	}
	matcher := paths.NewMatcher(badPathList)
	log.Informationf("french press: brewing against %d bad path(s)", len(badPathList))

	cfg := &tarpit.Config{
		MinDelay:      *minDelay,
		MaxDelay:      *maxDelay,
		MaxBrewTime:   *maxBrewTime,
		MaxConcurrent: *maxConcurrent,
		Log:           log,
	}

	var proxy *httputil.ReverseProxy
	if *backend != "" {
		backendURL, err := url.Parse(*backend)
		if err != nil {
			log.Fatalf("french press: invalid -backend URL: %v", err)
		}
		proxy = httputil.NewSingleHostReverseProxy(backendURL)
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		if matcher.Match(r.URL.Path) {
			tarpit.BrewHTTP(r.Context(), w, r, cfg)
			return
		}

		if proxy != nil {
			proxy.ServeHTTP(w, r)
			return
		}

		http.NotFound(w, r)
	}

	srv := &http.Server{
		Addr:    *addr,
		Handler: http.HandlerFunc(handler),
		// Deliberately no ReadTimeout/WriteTimeout: the tarpit handler
		// manages its own pacing via MaxBrewTime, and a server-wide
		// write timeout would cut brewing connections short.
	}

	go func() {
		log.Informationf("french press listening on %s", *addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("french press: %v", err)
		}
	}()

	// Graceful shutdown on Ctrl+C / SIGTERM.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	fmt.Println()
	log.Information("french press: shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}
