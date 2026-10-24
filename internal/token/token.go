// Package token mints and verifies xbl's own credentials: MSA access and
// refresh tokens, and the Xbox device, title, user and XSTS tokens. The
// clients treat every one of them as an opaque string; only xbl reads them.
// Format: base64url(JSON claims) "." base64url(HMAC-SHA256), key persisted.
package token

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Kinds of token.
const (
	MSAAccess  = "msa"
	MSARefresh = "msr"
	Device     = "dev"
	Title      = "tit"
	User       = "usr"
	XSTS       = "xst"
)

// Claims is what a token carries.
type Claims struct {
	Kind    string `json:"k"`
	Account string `json:"a,omitempty"`
	XUID    uint64 `json:"x,omitempty"`
	RP      string `json:"r,omitempty"`
	Device  string `json:"d,omitempty"`
	Title   string `json:"t,omitempty"`
	Scope   string `json:"s,omitempty"`
	Exp     int64  `json:"e"`
	Nonce   string `json:"n"`
}

// Expired reports whether the claims are past their expiry.
func (c *Claims) Expired(now time.Time) bool { return now.Unix() >= c.Exp }

// Signer holds the key.
type Signer struct{ key []byte }

// ErrInvalid is any token that does not verify.
var ErrInvalid = errors.New("token: invalid")

// Open loads stateDir/token.key, creating 32 random bytes the first time.
func Open(stateDir string) (*Signer, error) {
	p := filepath.Join(stateDir, "token.key")
	k, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		k = make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			return nil, err
		}
		if err := os.WriteFile(p, k, 0o600); err != nil {
			return nil, err
		}
		return &Signer{key: k}, nil
	}
	if err != nil {
		return nil, err
	}
	if len(k) < 32 {
		return nil, errors.New("token: key file is shorter than 32 bytes")
	}
	return &Signer{key: k}, nil
}

// NewSigner is for tests.
func NewSigner(key []byte) *Signer { return &Signer{key: key} }

// Mint issues a token valid for ttl.
func (s *Signer) Mint(c Claims, ttl time.Duration) string {
	c.Exp = time.Now().Add(ttl).Unix()
	n := make([]byte, 9)
	rand.Read(n)
	c.Nonce = base64.RawURLEncoding.EncodeToString(n)
	body, _ := json.Marshal(c)
	b := base64.RawURLEncoding.EncodeToString(body)
	return b + "." + s.mac(b)
}

// Verify checks the signature, kind and expiry.
func (s *Signer) Verify(tok, kind string) (*Claims, error) {
	b, m, ok := strings.Cut(tok, ".")
	if !ok || !hmac.Equal([]byte(m), []byte(s.mac(b))) {
		return nil, ErrInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(b)
	if err != nil {
		return nil, ErrInvalid
	}
	var c Claims
	if err := json.Unmarshal(raw, &c); err != nil || c.Kind != kind || c.Expired(time.Now()) {
		return nil, ErrInvalid
	}
	return &c, nil
}

func (s *Signer) mac(b string) string {
	h := hmac.New(sha256.New, s.key)
	h.Write([]byte(b))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// UserHash is the "uhs" claim: a stable, non-reversible tag of the user that
// pairs an XSTS token with its user in "XBL3.0 x=<uhs>;<token>".
func (s *Signer) UserHash(account string) string {
	h := hmac.New(sha256.New, s.key)
	h.Write([]byte("uhs:" + account))
	sum := h.Sum(nil)
	const digits = "0123456789"
	out := make([]byte, 19)
	for i := range out {
		out[i] = digits[int(sum[i])%10]
	}
	return string(out)
}
