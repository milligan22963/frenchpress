// Package logging builds French Press's pflog logger, either from a pflog
// YAML configuration file or, when none is given, a stdout-only default.
package logging

import (
	"os"
	"time"

	"github.com/PageFaultCode/pflog"
)

// Load returns a logger configured from the pflog YAML file at filename
// (see configs/log.example.yaml). An empty filename yields the default:
// text to stdout at Information, with the backlog dumped on Error.
func Load(filename string) (*pflog.Log, error) {
	if filename == "" {
		return defaultLogger()
	}

	var cfg pflog.Configuration
	if err := cfg.LoadConfigurationFile(filename); err != nil {
		// LoadConfiguration still builds a logger when only some output
		// targets failed; the whole thing failing is a config error either
		// way, so refuse rather than run with fewer targets than asked for.
		return nil, err
	}
	return cfg.GetLogger(), nil
}

func defaultLogger() (*pflog.Log, error) {
	log := pflog.New()
	// Trigger first: SetLevel refuses a level above the current trigger.
	if err := log.SetTriggerLevel(pflog.Error); err != nil {
		return nil, err
	}
	if err := log.SetLevel(pflog.Information); err != nil {
		return nil, err
	}
	formatter, err := pflog.CreateFormatter("text")
	if err != nil {
		return nil, err
	}
	formatter.SetTimestampFormat(time.RFC3339)
	log.AddOutputTargetAndFormatter(os.Stdout, formatter)
	return log, nil
}
