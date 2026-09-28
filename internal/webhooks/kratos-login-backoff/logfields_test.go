package kratosloginbackoff

import (
	"strings"
	"testing"
)

func TestIdentifierHash(t *testing.T) {
	key := []byte("test-key")

	h := identifierHash(key, "Someone@Example.org")
	if len(h) != 16 {
		t.Fatalf("want 16 hex chars, got %q", h)
	}
	if strings.Contains(h, "@") || strings.Contains(strings.ToLower(h), "example") {
		t.Fatalf("hash leaks the identifier: %q", h)
	}
	// Normalised: case and surrounding whitespace do not change the pseudonym,
	// so an attempt typed as "Someone@..." matches the stored "someone@...".
	if got := identifierHash(key, "  someone@example.org "); got != h {
		t.Fatalf("normalisation mismatch: %q vs %q", got, h)
	}
	// Keyed: a different key gives a different pseudonym (not reversible without the key).
	if identifierHash([]byte("other-key"), "someone@example.org") == h {
		t.Fatal("hash does not depend on the key")
	}
	// No key or no identifier: omit rather than fall back to an unkeyed hash.
	if identifierHash(nil, "someone@example.org") != "" || identifierHash(key, "  ") != "" {
		t.Fatal("expected empty hash without key or identifier")
	}
}

func TestIPPrefix(t *testing.T) {
	cases := map[string]string{
		"203.0.113.77":                 "203.0.113.0/24",
		" 10.1.2.3 ":                   "10.1.2.0/24",
		"2001:db8:abcd:12:34:56:78:9a": "2001:db8:abcd::/48",
		"::ffff:198.51.100.9":          "198.51.100.0/24",
		"":                             "",
		"not-an-ip":                    "",
		"203.0.113.77, 198.51.100.1":   "",
	}
	for in, want := range cases {
		if got := ipPrefix(in); got != want {
			t.Errorf("ipPrefix(%q) = %q, want %q", in, got, want)
		}
	}
}
