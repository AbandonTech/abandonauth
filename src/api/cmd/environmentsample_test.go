package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sampleEnvironmentPath is the placeholder file an operator copies to make a
// deployment's own environment. It sits at the repository root.
var sampleEnvironmentPath = filepath.Join("..", "..", "..", ".env.sample")

// sampleEnvironment reads the sample as name/value pairs. Values are returned
// so that a credential committed by accident can be caught; no test prints one.
func sampleEnvironment(t *testing.T) map[string]string {
	t.Helper()

	contents, err := os.ReadFile(sampleEnvironmentPath)
	if err != nil {
		t.Fatalf("reading the sample environment: %v", err)
	}

	entries := make(map[string]string)

	for _, line := range strings.Split(string(contents), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		name, value, separated := strings.Cut(trimmed, "=")
		if !separated {
			t.Errorf("a line of the sample environment is not NAME=VALUE")

			continue
		}

		entries[strings.TrimSpace(name)] = strings.TrimSpace(value)
	}

	return entries
}

func TestTheSampleEnvironmentNamesEverySetting(t *testing.T) {
	declared := sampleEnvironment(t)

	for _, flag := range settingFlags() {
		read, ok := flag.(interface{ GetEnvVars() []string })
		if !ok {
			t.Errorf("flag %v reads no environment variable", flag.Names())

			continue
		}

		for _, name := range read.GetEnvVars() {
			if _, present := declared[name]; !present {
				t.Errorf("%s configures the service but the sample environment does not list it", name)
			}
		}
	}
}

func TestTheSampleEnvironmentSuppliesNoProviderCredential(t *testing.T) {
	for name, value := range sampleEnvironment(t) {
		if !strings.HasSuffix(name, "_CLIENT_SECRET") {
			continue
		}

		if value != "" {
			t.Errorf("%s has a value in the sample environment; it must be filled in per deployment", name)
		}
	}
}
