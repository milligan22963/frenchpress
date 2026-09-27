package paths

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaultsOnly(t *testing.T) {
	got, err := Load("", true, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != len(DefaultPaths) {
		t.Fatalf("expected %d defaults, got %d", len(DefaultPaths), len(got))
	}
}

func TestLoadFileMergesDefaults(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "bad.yaml")
	content := "paths:\n  - /my-custom-path\n"
	if err := os.WriteFile(f, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	got, err := Load(f, true, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, p := range got {
		if p == "/my-custom-path" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected /my-custom-path in merged list, got %v", got)
	}
	if len(got) != len(DefaultPaths)+1 {
		t.Errorf("expected defaults + 1 custom path, got %d entries", len(got))
	}
}

func TestLoadFileExcludesDefaultsViaYAML(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "bad.yaml")
	content := "include_defaults: false\npaths:\n  - /only-this-one\n"
	if err := os.WriteFile(f, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	got, err := Load(f, true, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0] != "/only-this-one" {
		t.Errorf("expected exactly [/only-this-one], got %v", got)
	}
}

func TestLoadFileFlagOverridesYAML(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "bad.yaml")
	// YAML says exclude defaults, but the CLI flag explicitly says include.
	content := "include_defaults: false\npaths:\n  - /only-this-one\n"
	if err := os.WriteFile(f, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	got, err := Load(f, true, true) // flagSet=true, includeDefaultsFlag=true
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != len(DefaultPaths)+1 {
		t.Errorf("expected flag to override YAML and include defaults, got %d entries", len(got))
	}
}

func TestLoadDeduplicates(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "bad.yaml")
	// Duplicate one of the built-in defaults on purpose.
	content := "paths:\n  - /wp-admin\n  - /wp-admin\n  - /new-one\n"
	if err := os.WriteFile(f, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	got, err := Load(f, true, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	count := 0
	for _, p := range got {
		if p == "/wp-admin" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected /wp-admin to appear exactly once, got %d", count)
	}
}

func TestMatcher(t *testing.T) {
	m := NewMatcher([]string{"/wp-admin", "/.env"})
	cases := map[string]bool{
		"/wp-admin/login.php": true,
		"/.env":               true,
		"/.environment":       true, // prefix match is intentionally loose
		"/index.html":         false,
		"/":                   false,
	}
	for path, want := range cases {
		if got := m.Match(path); got != want {
			t.Errorf("Match(%q) = %v, want %v", path, got, want)
		}
	}
}
