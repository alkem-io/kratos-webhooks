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

// identifierHash returns a keyed pseudonym for an identifier: the first 16 hex
// characters of HMAC-SHA256(key, lower(trim(identifier))). Without a key the
// field is omitted (empty), never an unkeyed hash, since an unkeyed hash of an
// email address can be reversed with a list of emails.
func identifierHash(key []byte, identifier string) string {
	normalised := strings.ToLower(strings.TrimSpace(identifier))
	if len(key) == 0 || normalised == "" {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(normalised))
	return hex.EncodeToString(mac.Sum(nil))[:16]
}

// ipPrefix truncates an IP to its network prefix (/24 for IPv4, /48 for IPv6),
// enough to see where attack traffic comes from without logging a person's
// address. Unparseable input yields "".
func ipPrefix(ip string) string {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return ""
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4.Mask(net.CIDRMask(24, 32)).String() + "/24"
	}
	return parsed.Mask(net.CIDRMask(48, 128)).String() + "/48"
}
