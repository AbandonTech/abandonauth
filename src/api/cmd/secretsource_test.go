package main

import (
	"slices"
	"strings"
	"testing"
)

// removedSecretFlags are the command-line names a deployment might still try to
// pass a secret with. Each carries a value distinctive enough that finding it in
// any output proves it was echoed.
var removedSecretFlags = map[string]string{
	"database-url":          "postgres://placeholder:flag-supplied-database-password@127.0.0.1:5432/abandonauth",
	"jwt-secret":            "flag-supplied-signing-secret-flag-supplied-signing-secret-value",
	"discord-client-secret": "flag-supplied-discord-client-secret",
	"github-client-secret":  "flag-supplied-github-client-secret",
	"google-client-secret":  "flag-supplied-google-client-secret",
}

// A secret passed as an argument is readable by every process on the machine, so
// the flags that once accepted one are refused. The refusal must not repeat the
// value, which would write the secret to the log of whatever started the
// service.
func TestSecretsSuppliedOnTheCommandLineAreRefusedWithoutBeingEchoed(t *testing.T) {
	for flag, value := range removedSecretFlags {
		t.Run(flag, func(t *testing.T) {
			applyEnvironment(t, placeholderEnvironment())

			perform, err := runCommand(t, "serve", "--"+flag+"="+value)
			if err == nil {
				t.Fatalf("--%s was accepted", flag)
			}

			if perform.served {
				t.Errorf("--%s was refused but the service started anyway", flag)
			}

			if strings.Contains(err.Error(), value) {
				t.Errorf("the refusal of --%s repeated the value it was given", flag)
			}

			if !strings.Contains(err.Error(), flag) {
				t.Errorf("the refusal of --%s does not name the flag: %v", flag, err)
			}
		})
	}
}

// The command-line surface is what `--help` prints and what a deployment can be
// configured with, so a secret must be absent from it rather than merely
// undocumented.
func TestTheCommandLineOffersNoSecret(t *testing.T) {
	secrets := secretEnvironment()

	for _, flag := range settingFlags() {
		for _, name := range flag.Names() {
			if _, removed := removedSecretFlags[name]; removed {
				t.Errorf("--%s accepts a secret on the command line", name)
			}
		}

		read, ok := flag.(interface{ GetEnvVars() []string })
		if !ok {
			continue
		}

		for _, name := range read.GetEnvVars() {
			if slices.Contains(secrets, name) {
				t.Errorf("%s is read through a command-line flag as well as the environment", name)
			}
		}
	}
}

// Every secret must still reach the configuration from its environment variable,
// and an absent one must fail start-up naming only the variable.
func TestAnAbsentSecretFailsStartUpNamingOnlyItsVariable(t *testing.T) {
	for _, secret := range secretEnvironment() {
		t.Run(secret, func(t *testing.T) {
			environment := placeholderEnvironment()
			supplied := environment[secret]

			if supplied == "" {
				t.Fatalf("%s is not part of the placeholder environment", secret)
			}

			delete(environment, secret)
			applyEnvironment(t, environment)
			t.Setenv(secret, "")

			perform, err := runCommand(t, "serve")
			if err == nil {
				t.Fatalf("serve started without %s", secret)
			}

			if perform.served {
				t.Errorf("serve reported a failure for %s but ran anyway", secret)
			}

			if !strings.Contains(err.Error(), secret) {
				t.Errorf("the failure does not name %s: %v", secret, err)
			}

			if strings.Contains(err.Error(), supplied) {
				t.Errorf("the failure for %s repeated a value", secret)
			}
		})
	}
}
