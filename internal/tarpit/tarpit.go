// Package tarpit implements the slow-drip connection handlers: raw TCP and
// HTTP-chunked variants that hold a connection open and dribble bytes at a
// deliberately glacial pace, tying up whatever scanner or bot connected.
package tarpit

import (
	"bufio"
	"context"
	"math/rand"
	"net"
	"net/http"
	"time"

	"github.com/PageFaultCode/pflog"
)

// Config controls brewing behavior. All fields have sane defaults applied
// by DefaultConfig; zero-value Config is not safe to use directly.
type Config struct {
	// MinDelay/MaxDelay bound the random pause between drips.
	MinDelay time.Duration
	MaxDelay time.Duration

	// MaxBrewTime is the hard cap on how long a single connection is held
	// open, regardless of whether the peer is still reading.
	MaxBrewTime time.Duration

	// MaxConcurrent limits how many connections may be brewing at once,
	// across all listeners sharing this Config's semaphore. Zero means
	// unlimited (not recommended on anything internet-facing).
	MaxConcurrent int

	// Log receives brew start/end and capacity events. Nil discards.
	Log *pflog.Log

	sem chan struct{}
}

// DefaultConfig returns reasonable defaults: 0.5-2s between drips, a 10
// minute hard cap per connection, and up to 500 concurrent brews.
func DefaultConfig() *Config {
	c := &Config{
		MinDelay:      500 * time.Millisecond,
		MaxDelay:      2 * time.Second,
		MaxBrewTime:   10 * time.Minute,
		MaxConcurrent: 500,
	}
	c.init()
	return c
}

func (c *Config) init() {
	if c.MaxConcurrent > 0 && c.sem == nil {
		c.sem = make(chan struct{}, c.MaxConcurrent)
	}
}

func (c *Config) acquire() bool {
	c.init()
	if c.sem == nil {
		return true
	}
	select {
	case c.sem <- struct{}{}:
		return true
	default:
		return false
	}
}

func (c *Config) release() {
	if c.sem != nil {
		select {
		case <-c.sem:
		default:
		}
	}
}

// discardLog backs a nil Config.Log: a pflog.Log with no output targets
// writes nothing.
var discardLog = pflog.New()

func (c *Config) logger() *pflog.Log {
	if c.Log == nil {
		return discardLog
	}
	return c.Log
}

// logHeld records how long a brewed connection was held and why it ended —
// the per-connection dataset the tarpit exists to produce.
func logHeld(log *pflog.Log, addr string, start time.Time, outcome *string) {
	log.Informationf("french press: %s held %s (%s)", addr, time.Since(start).Round(time.Second), *outcome)
}

func (c *Config) randomDelay() time.Duration {
	span := c.MaxDelay - c.MinDelay
	if span <= 0 {
		return c.MinDelay
	}
	return c.MinDelay + time.Duration(rand.Int63n(int64(span)))
}

// BrewRaw holds a raw TCP connection open and dribbles a random byte at a
// time, forever, until MaxBrewTime elapses or the peer disconnects. Useful
// behind a listener that isn't speaking HTTP (SSH probes, generic port
// scanners, etc.).
func BrewRaw(ctx context.Context, conn net.Conn, cfg *Config) {
	defer conn.Close()
	addr := conn.RemoteAddr().String()
	log := cfg.logger()

	if !cfg.acquire() {
		log.Warningf("french press: at capacity, dropping %s", addr)
		return
	}
	defer cfg.release()

	log.Informationf("french press: brewing raw connection from %s", addr)
	outcome := "context cancelled"
	defer logHeld(log, addr, time.Now(), &outcome)

	w := bufio.NewWriter(conn)

	// Read (and discard) whatever the peer sent, so the connection looks
	// alive rather than instantly suspicious. We don't care about the
	// content, just that we drained it.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	discard := make([]byte, 1024)
	conn.Read(discard) //nolint:errcheck

	deadline := time.Now().Add(cfg.MaxBrewTime)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if _, err := w.Write([]byte{byte(rand.Intn(256))}); err != nil {
			outcome = "peer gave up"
			return
		}
		if err := w.Flush(); err != nil {
			outcome = "peer gave up on flush"
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(cfg.randomDelay()):
		}
	}
	outcome = "brewed to completion (rare)"
}

// BrewHTTP holds an HTTP connection open using chunked transfer-encoding and
// dribbles a one-byte chunk at a time, never sending the terminating chunk,
// until MaxBrewTime elapses or the peer disconnects.
//
// It writes the response directly to the underlying connection (via
// http.Hijacker), because net/http's normal ResponseWriter machinery
// doesn't let us hold a response open indefinitely without a handler
// goroutine blocking in a way the stdlib is happy with — hijacking gives
// full control over pacing.
func BrewHTTP(ctx context.Context, w http.ResponseWriter, r *http.Request, cfg *Config) {
	addr := r.RemoteAddr
	log := cfg.logger()

	if !cfg.acquire() {
		log.Warningf("french press: at capacity, dropping %s %s from %s", r.Method, r.URL.Path, addr)
		http.Error(w, "", http.StatusServiceUnavailable)
		return
	}
	defer cfg.release()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		// Fallback for a ResponseWriter that can't be hijacked (rare, e.g.
		// under some test harnesses): just stall the handler goroutine
		// itself using chunked encoding via the normal Flusher path.
		brewHTTPFallback(ctx, w, cfg)
		return
	}

	conn, bufrw, err := hijacker.Hijack()
	if err != nil {
		log.Warningf("french press: hijack failed for %s: %v", addr, err)
		return
	}
	defer conn.Close()

	log.Informationf("french press: brewing HTTP request %s %s from %s", r.Method, r.URL.Path, addr)
	outcome := "context cancelled"
	defer logHeld(log, addr, time.Now(), &outcome)

	headers := "HTTP/1.1 200 OK\r\n" +
		"Server: Apache\r\n" +
		"Content-Type: text/html\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"Connection: close\r\n\r\n"
	if _, err := bufrw.WriteString(headers); err != nil {
		outcome = "peer gave up"
		return
	}
	if err := bufrw.Flush(); err != nil {
		outcome = "peer gave up on flush"
		return
	}

	deadline := time.Now().Add(cfg.MaxBrewTime)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// One-byte chunk: size line, the byte, trailing CRLF.
		if _, err := bufrw.WriteString("1\r\nX\r\n"); err != nil {
			outcome = "peer gave up"
			return
		}
		if err := bufrw.Flush(); err != nil {
			outcome = "peer gave up on flush"
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(cfg.randomDelay()):
		}
	}
	// Deliberately never send the "0\r\n\r\n" terminating chunk — we just
	// let the deadline (or the peer) close the connection.
	outcome = "brewed to completion (rare)"
}

// brewHTTPFallback stalls using the standard http.Flusher interface when
// hijacking isn't available. Less precise timing control, but works
// anywhere net/http does.
func brewHTTPFallback(ctx context.Context, w http.ResponseWriter, cfg *Config) {
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Server", "Apache")
	w.WriteHeader(http.StatusOK)

	flusher, ok := w.(http.Flusher)
	deadline := time.Now().Add(cfg.MaxBrewTime)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if _, err := w.Write([]byte{byte('X')}); err != nil {
			return
		}
		if ok {
			flusher.Flush()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(cfg.randomDelay()):
		}
	}
}
