package config

import (
	"strings"
	"testing"
)

// The service must refuse to start without a strong log hash key: without one,
// identifier_hmac is either missing or brute-forceable from a list of emails.
func TestValidateRequiresStrongLogHashKey(t *testing.T) {
	valid := func(key string) *Config {
		return &Config{
			LoginBackoffMaxIdentifierAttempts:    10,
			LoginBackoffMaxIPAttempts:            20,
			LoginBackoffIdentifierLockoutSeconds: 120,
			LoginBackoffIPLockoutSeconds:         120,
			KratosInternalURL:                    "http://kratos:4433",
			LogIdentifierHashKey:                 key,
		}
	}
	for name, key := range map[string]string{"empty": "", "short": "alkemio"} {
		if err := validateLoginBackoffConfig(valid(key)); err == nil {
			t.Errorf("%s key accepted", name)
		}
	}
	if err := validateLoginBackoffConfig(valid(strings.Repeat("k", 32))); err != nil {
		t.Errorf("32-byte key rejected: %v", err)
	}
}

// A secret file usually ends in a newline; it must not become part of the key.
func TestLoadTrimsLogHashKey(t *testing.T) {
	key := strings.Repeat("k", 32)
	t.Setenv("LOG_IDENTIFIER_HASH_KEY", key+"\n")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogIdentifierHashKey != key {
		t.Fatalf("key not trimmed: %q", cfg.LogIdentifierHashKey)
	}
}
