package kratosloginbackoff

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strings"
)

// Log fields must not identify a person. These helpers are used ONLY for log
// output; lockout counting still uses the raw identifier and IP (in Redis, with
// a short TTL).

// normaliseIdentifier is the one canonical form of a login identifier, used for
// the Redis counter keys and the log pseudonym alike, so an attempt typed as
// "Someone@..." counts and hashes the same as the stored "someone@...".
// External consumers recomputing identifier_hmac must apply exactly this.
func normaliseIdentifier(identifier string) string {
	return strings.ToLower(strings.TrimSpace(identifier))
}

// identifierHash returns a keyed pseudonym for an already-normalised
// identifier: the first 16 hex characters of HMAC-SHA256(key, identifier).
// Without a key the result is empty (field omitted), never an unkeyed hash,
// since an unkeyed hash of an email address can be reversed with a list of emails.
func identifierHash(key []byte, identifier string) string {
	if len(key) == 0 || identifier == "" {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(identifier))
	return hex.EncodeToString(mac.Sum(nil))[:16]
}

// ipPrefix truncates an IP to its network prefix (/24 for IPv4, /32 for IPv6),
// enough to see where attack traffic comes from without logging a person's
// address. IPv6 stops at /32 because a /48 is often one subscriber's whole
// delegation, and 6to4 (2002::/16) carries the client's IPv4 in bits 16-47.
// Unparseable input yields "".
func ipPrefix(ip string) string {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return ""
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4.Mask(net.CIDRMask(24, 32)).String() + "/24"
	}
	return parsed.Mask(net.CIDRMask(32, 128)).String() + "/32"
}
