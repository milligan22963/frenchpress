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
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/milligan22963/french-press/internal/logging"
	"github.com/milligan22963/french-press/internal/paths"
	"github.com/milligan22963/french-press/internal/tarpit"
)

// version is set at release build time via -ldflags "-X main.version=...".
var version = "dev"

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
		tlsCert         = flag.String("tls-cert", "", "PEM certificate file; with -tls-key, serves HTTPS on -addr")
		tlsKey          = flag.String("tls-key", "", "PEM private key file for -tls-cert")
		autocertHosts   = flag.String("autocert", "", "comma-separated hostnames to fetch Let's Encrypt certificates for; serves HTTPS on -addr (mutually exclusive with -tls-cert/-tls-key)")
		autocertCache   = flag.String("autocert-cache", "autocert-cache", "directory to cache -autocert certificates in")
		autocertEmail   = flag.String("autocert-email", "", "contact email registered with Let's Encrypt for -autocert (optional)")
		redirectAddr    = flag.String("redirect-addr", "", "with TLS enabled, also listen for plain HTTP here (e.g. :80): bad paths are tarpitted, everything else is redirected to HTTPS; required for -autocert HTTP-01 challenges")
		trustForwarded  = flag.Bool("trust-forwarded", false, "keep incoming X-Forwarded-Proto/X-Forwarded-Host instead of overwriting them; enable only when French Press sits behind a proxy you control")
		readHdrTimeout  = flag.Duration("read-header-timeout", 10*time.Second, "time allowed to read request headers; guards proxied traffic against slowloris clients")
		showVersion     = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println("french press", version)
		return
	}

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

	if (*tlsCert == "") != (*tlsKey == "") {
		log.Fatal("french press: -tls-cert and -tls-key must be given together")
	}
	if *tlsCert != "" && *autocertHosts != "" {
		log.Fatal("french press: -autocert cannot be combined with -tls-cert/-tls-key")
	}
	useTLS := *tlsCert != "" || *autocertHosts != ""
	if *redirectAddr != "" && !useTLS {
		log.Fatal("french press: -redirect-addr needs TLS (-tls-cert/-tls-key or -autocert)")
	}

	var proxy *httputil.ReverseProxy
	if *backend != "" {
		backendURL, err := url.Parse(*backend)
		if err != nil {
			log.Fatalf("french press: invalid -backend URL: %v", err)
		}
		proxy = httputil.NewSingleHostReverseProxy(backendURL)
		direct := proxy.Director
		proxy.Director = func(r *http.Request) {
			direct(r)
			// r is a clone of the inbound request, so r.TLS and r.Host
			// still describe the client's connection to us.
			if *trustForwarded && r.Header.Get("X-Forwarded-Proto") != "" {
				return
			}
			proto := "http"
			if r.TLS != nil {
				proto = "https"
			}
			r.Header.Set("X-Forwarded-Proto", proto)
			r.Header.Set("X-Forwarded-Host", r.Host)
		}
	}

	// brewOr tarpits bad paths and hands everything else to next.
	brewOr := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if matcher.Match(r.URL.Path) {
				tarpit.BrewHTTP(r.Context(), w, r, cfg)
				return
			}
			next.ServeHTTP(w, r)
		})
	}

	var fallback http.Handler = http.HandlerFunc(http.NotFound)
	if proxy != nil {
		fallback = proxy
	}

	srv := newServer(*addr, brewOr(fallback), *readHdrTimeout)

	var redirectSrv *http.Server
	if useTLS {
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}

		var redirect http.Handler = http.HandlerFunc(redirectToHTTPS(*addr))
		if *autocertHosts != "" {
			m := &autocert.Manager{
				Prompt:     autocert.AcceptTOS,
				HostPolicy: autocert.HostWhitelist(splitHosts(*autocertHosts)...),
				Cache:      autocert.DirCache(*autocertCache),
				Email:      *autocertEmail,
			}
			srv.TLSConfig = m.TLSConfig()
			srv.TLSConfig.MinVersion = tls.VersionTLS12
			// Answers HTTP-01 challenges, passes everything else on.
			redirect = m.HTTPHandler(redirect)
		}

		if *redirectAddr != "" {
			// Bad paths are checked before the ACME handler, and ACME's
			// /.well-known/acme-challenge/ is never on the bad-path list.
			redirectSrv = newServer(*redirectAddr, brewOr(redirect), *readHdrTimeout)
			go func() {
				log.Informationf("french press redirecting HTTP on %s", *redirectAddr)
				if err := redirectSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
					log.Fatalf("french press: %v", err)
				}
			}()
		}
	}

	go func() {
		var err error
		if useTLS {
			log.Informationf("french press listening on %s (TLS)", *addr)
			// Empty filenames are fine when TLSConfig supplies certificates
			// (autocert).
			err = srv.ListenAndServeTLS(*tlsCert, *tlsKey)
		} else {
			log.Informationf("french press listening on %s", *addr)
			err = srv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
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
	if redirectSrv != nil {
		_ = redirectSrv.Shutdown(ctx)
	}
}

func newServer(addr string, h http.Handler, readHeaderTimeout time.Duration) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       2 * time.Minute,
		// Deliberately no ReadTimeout/WriteTimeout: the tarpit handler
		// manages its own pacing via MaxBrewTime, and a server-wide
		// write timeout would cut brewing connections short.
	}
}

// redirectToHTTPS sends plain-HTTP requests to the same host and path over
// HTTPS, carrying over tlsAddr's port unless it is the default 443.
func redirectToHTTPS(tlsAddr string) http.HandlerFunc {
	_, port, _ := net.SplitHostPort(tlsAddr)
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if port != "" && port != "443" {
			host = net.JoinHostPort(host, port)
		}
		target := url.URL{Scheme: "https", Host: host, Path: r.URL.Path, RawQuery: r.URL.RawQuery}
		http.Redirect(w, r, target.String(), http.StatusMovedPermanently)
	}
}

func splitHosts(s string) []string {
	var hosts []string
	for _, h := range strings.Split(s, ",") {
		if h = strings.TrimSpace(h); h != "" {
			hosts = append(hosts, h)
		}
	}
	return hosts
}
