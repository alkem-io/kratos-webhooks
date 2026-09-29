package config

import (
	"strings"
	"testing"
)

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
