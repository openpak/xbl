// Package ident gives every OpenPak account its modern Xbox identity: an XUID
// and a gamertag. The XUID is derived from the account id (stable, nothing to
// provision); the gamertag is the account's handle, else its display name.
// The reverse map XUID -> account is remembered in a small state file so a
// friend's XUID handed out once can be resolved again after a restart.
package ident

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openpak/xbl/internal/core"
)

// Core is the part of the account core ident needs.
type Core interface {
	GetAccount(ctx context.Context, account string) (*core.Account, error)
}

// User is one resolved identity.
type User struct {
	AccountID string
	XUID      uint64
	Gamertag  string
	Country   string
	Bio       string
}

// XUIDString is the decimal form used on the wire.
func (u *User) XUIDString() string { return strconv.FormatUint(u.XUID, 10) }

// ErrUnknown means no account is known for an XUID or gamertag.
var ErrUnknown = errors.New("ident: unknown user")

// Directory resolves identities.
type Directory struct {
	core Core
	path string

	mu    sync.Mutex
	byX   map[uint64]string // xuid -> account
	cache map[string]cached // account -> user
	dirty bool
}

type cached struct {
	u  User
	at time.Time
}

// XUIDFor derives the XUID of an account: the 0x0009 prefix every retail
// XUID carries, then 48 bits of SHA-256 over the account id.
func XUIDFor(account string) uint64 {
	h := sha256.Sum256([]byte("openpak-xbl-xuid:" + account))
	return 0x0009<<48 | binary.BigEndian.Uint64(h[:8])>>16
}

// XUIDForString is XUIDFor in decimal.
func XUIDForString(account string) string { return strconv.FormatUint(XUIDFor(account), 10) }

// Open loads (or starts) the reverse map in stateDir.
func Open(c Core, stateDir string) (*Directory, error) {
	d := &Directory{core: c, path: filepath.Join(stateDir, "xuids.json"), byX: map[uint64]string{}, cache: map[string]cached{}}
	b, err := os.ReadFile(d.path)
	if errors.Is(err, os.ErrNotExist) {
		return d, nil
	}
	if err != nil {
		return nil, err
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("ident: %s: %w", d.path, err)
	}
	for k, v := range m {
		x, err := strconv.ParseUint(k, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("ident: %s: bad xuid %q", d.path, k)
		}
		d.byX[x] = v
	}
	return d, nil
}

// ByAccount resolves an account (cached for a minute).
func (d *Directory) ByAccount(ctx context.Context, account string) (*User, error) {
	d.mu.Lock()
	if c, ok := d.cache[account]; ok && time.Since(c.at) < time.Minute {
		d.mu.Unlock()
		u := c.u
		return &u, nil
	}
	d.mu.Unlock()
	a, err := d.core.GetAccount(ctx, account)
	if err != nil {
		return nil, err
	}
	u := User{AccountID: account, XUID: XUIDFor(account), Gamertag: Gamertag(a), Country: a.Country, Bio: a.Bio}
	d.mu.Lock()
	d.cache[account] = cached{u: u, at: time.Now()}
	if d.byX[u.XUID] != account {
		d.byX[u.XUID] = account
		d.dirty = true
	}
	d.mu.Unlock()
	return &u, nil
}

// ByXUID resolves an XUID handed out before.
func (d *Directory) ByXUID(ctx context.Context, xuid uint64) (*User, error) {
	d.mu.Lock()
	acct, ok := d.byX[xuid]
	d.mu.Unlock()
	if !ok {
		return nil, ErrUnknown
	}
	return d.ByAccount(ctx, acct)
}

// ByGamertag resolves a gamertag among the identities seen so far.
func (d *Directory) ByGamertag(ctx context.Context, tag string) (*User, error) {
	d.mu.Lock()
	var acct string
	for a, c := range d.cache {
		if strings.EqualFold(c.u.Gamertag, tag) {
			acct = a
			break
		}
	}
	d.mu.Unlock()
	if acct == "" {
		return nil, ErrUnknown
	}
	return d.ByAccount(ctx, acct)
}

// Flush writes the reverse map when it changed.
func (d *Directory) Flush() error {
	d.mu.Lock()
	if !d.dirty {
		d.mu.Unlock()
		return nil
	}
	m := make(map[string]string, len(d.byX))
	for k, v := range d.byX {
		m[strconv.FormatUint(k, 10)] = v
	}
	d.dirty = false
	d.mu.Unlock()
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	tmp := d.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, d.path)
}

// Gamertag picks the public name: the handle, else the display name, else a
// generated one. Gamertags are at most 15 characters.
func Gamertag(a *core.Account) string {
	for _, s := range []string{a.Handle, a.DisplayName} {
		s = strings.TrimSpace(s)
		if s != "" {
			if r := []rune(s); len(r) > 15 {
				s = string(r[:15])
			}
			return s
		}
	}
	return fmt.Sprintf("Player%04X", XUIDFor(a.ID)&0xffff)
}
