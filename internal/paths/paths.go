// Package paths loads the list of "bad paths" — request paths that mark a
// caller as an unsolicited scanner or bot rather than a legitimate visitor.
// French Press routes any request matching one of these into the tarpit
// instead of a real backend.
package paths

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// DefaultPaths is the built-in list of well-known scanner targets:
// CMS admin panels, credential/config files, and common exploit probes.
// Kept small and boring on purpose — this is bait for automated noise,
// not a full threat feed.
var DefaultPaths = []string{
	"/wp-admin",
	"/wp-login.php",
	"/xmlrpc.php",
	"/.env",
	"/.git/config",
	"/phpmyadmin",
	"/administrator/index.php",
	"/config.json",
	"/.aws/credentials",
	"/actuator/env",
	"/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
	"/cgi-bin/",
	"/.well-known/acme-challenge/../../etc/passwd",
	"/console/",
	"/telescope/requests",
}

// Config is the shape of the bad-paths file.
//
//	paths:
//	  - /custom-bad-path
//	  - /another-one
//	include_defaults: true   # optional, defaults to true when omitted
type Config struct {
	Paths           []string
	IncludeDefaults *bool
}

// parseConfig parses the narrow YAML subset French Press's bad-paths file
// uses: a top-level "include_defaults: <bool>" scalar and a top-level
// "paths:" key followed by "- /some/path" list items. This intentionally
// avoids pulling in a full YAML library — the format is simple and fixed,
// and a hand-rolled parser keeps the module dependency-free so it builds
// anywhere with just the Go toolchain.
//
// Anything outside this shape (nested maps, flow sequences, multi-line
// strings, etc.) is not supported and will either be ignored or produce a
// parse error.
func parseConfig(data []byte) (Config, error) {
	var cfg Config

	scanner := bufio.NewScanner(bytes.NewReader(data))
	inPathsList := false

	for scanner.Scan() {
		rawLine := scanner.Text()

		// Strip full-line and trailing comments (simple '#' rule; fine for
		// this format since paths won't legitimately contain '#').
		line := rawLine
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		// A list item under "paths:".
		if strings.HasPrefix(trimmed, "- ") {
			if !inPathsList {
				return cfg, fmt.Errorf("unexpected list item %q outside of a \"paths:\" block", trimmed)
			}
			item := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
			item = unquote(item)
			cfg.Paths = append(cfg.Paths, item)
			continue
		}

		// A top-level "key:" or "key: value" line ends any list we were in.
		inPathsList = false

		key, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			return cfg, fmt.Errorf("could not parse line: %q", rawLine)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		switch key {
		case "paths":
			if value != "" && value != "[]" {
				return cfg, fmt.Errorf("inline \"paths:\" values are not supported; use a \"- /path\" list on following lines")
			}
			inPathsList = true
		case "include_defaults":
			b, err := strconv.ParseBool(value)
			if err != nil {
				return cfg, fmt.Errorf("invalid include_defaults value %q: %w", value, err)
			}
			cfg.IncludeDefaults = &b
		default:
			// Unknown key: ignore rather than fail, so the format has room
			// to grow without breaking on older/newer files.
		}
	}
	if err := scanner.Err(); err != nil {
		return cfg, err
	}

	return cfg, nil
}

// unquote strips a single layer of matching single or double quotes, if
// present, from a scalar value.
func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// Load reads bad paths from the given YAML file. If path is empty, it
// returns a copy of DefaultPaths. includeDefaultsFlag is the value of the
// -include-defaults CLI flag; flagSet reports whether the user passed it
// explicitly, which lets the flag override the file's include_defaults
// setting when both are present.
func Load(path string, includeDefaultsFlag bool, flagSet bool) ([]string, error) {
	if path == "" {
		return append([]string(nil), DefaultPaths...), nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading bad-paths file %q: %w", path, err)
	}

	cfg, err := parseConfig(data)
	if err != nil {
		return nil, fmt.Errorf("parsing bad-paths file %q: %w", path, err)
	}

	// Decide whether defaults are included:
	// 1. An explicit -include-defaults flag on the CLI always wins.
	// 2. Otherwise, the file's include_defaults field (if set) applies.
	// 3. Otherwise, default to true (defaults are included).
	includeDefaults := true
	switch {
	case flagSet:
		includeDefaults = includeDefaultsFlag
	case cfg.IncludeDefaults != nil:
		includeDefaults = *cfg.IncludeDefaults
	}

	seen := make(map[string]bool)
	var merged []string

	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		merged = append(merged, p)
	}

	if includeDefaults {
		for _, p := range DefaultPaths {
			add(p)
		}
	}
	for _, p := range cfg.Paths {
		add(p)
	}

	return merged, nil
}

// Matcher checks whether a request path should be brewed.
type Matcher struct {
	prefixes []string
}

// NewMatcher builds a Matcher from a list of path prefixes.
func NewMatcher(pathList []string) *Matcher {
	return &Matcher{prefixes: pathList}
}

// Match reports whether reqPath starts with any configured bad-path prefix.
func (m *Matcher) Match(reqPath string) bool {
	for _, p := range m.prefixes {
		if strings.HasPrefix(reqPath, p) {
			return true
		}
	}
	return false
}
