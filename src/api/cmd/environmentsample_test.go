package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abandontech/abandonauth/src/api/internal/urlpolicy"
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

	// The secrets have no flag to be discovered through, so they are checked
	// against their own list or nothing would notice one going missing.
	for _, name := range secretEnvironment() {
		if _, present := declared[name]; !present {
			t.Errorf("%s configures the service but the sample environment does not list it", name)
		}
	}
}

// An operator copies the sample and fills in the credentials, so a callback in
// it that the service would refuse costs them a failed start-up to discover.
func TestTheSampleEnvironmentsCallbacksAreOnesTheServiceAccepts(t *testing.T) {
	declared := sampleEnvironment(t)

	found := 0

	for name, value := range declared {
		if !strings.HasSuffix(name, "_CALLBACK") {
			continue
		}

		found++

		if _, err := urlpolicy.ParseCallbackURI(value); err != nil {
			t.Errorf("the sample's %s is not a callback this service would accept: %v", name, err)
		}
	}

	if found == 0 {
		t.Error("the sample environment declares no provider callback")
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
