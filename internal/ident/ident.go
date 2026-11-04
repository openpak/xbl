// Package ident gives every OpenPak account its modern Xbox identity: an XUID
// and a gamertag. The XUID is derived from the account id (stable, nothing to
// provision); the gamertag is the account's handle, else its display name.
// The reverse map XUID -> account is remembered in Postgres (schema xbl of the
// shared "xbox" database) so a friend's XUID handed out once can be resolved
// again after a restart.
package ident

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openpak/xbl/internal/core"
	"github.com/openpak/xbl/internal/pgdb"
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
	db   *pgdb.DB

	mu    sync.Mutex
	byX   map[uint64]string // xuid -> account
	cache map[string]cached // account -> user
	dirty map[uint64]string // learned but not yet written
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

// Open connects to the Postgres at dsn (schema xbl unless the DSN sets a
// search_path), creates the table and loads the reverse map.
func Open(c Core, dsn string) (*Directory, error) {
	db, err := pgdb.Open(dsn, "xbl", `CREATE TABLE IF NOT EXISTS xuid_map(
 xuid TEXT PRIMARY KEY, account TEXT NOT NULL, created BIGINT NOT NULL);
CREATE INDEX IF NOT EXISTS xuid_map_account ON xuid_map(account)`)
	if err != nil {
		return nil, err
	}
	d := &Directory{core: c, db: db, byX: map[uint64]string{}, cache: map[string]cached{}, dirty: map[uint64]string{}}
	rows, err := db.Query(`SELECT xuid, account FROM xuid_map`)
	if err != nil {
		db.Close()
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			db.Close()
			return nil, err
		}
		x, err := strconv.ParseUint(k, 10, 64)
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("ident: bad xuid %q in xuid_map", k)
		}
		d.byX[x] = v
	}
	if err := rows.Err(); err != nil {
		db.Close()
		return nil, err
	}
	return d, nil
}

// Close flushes and closes the database.
func (d *Directory) Close() error {
	err := d.Flush()
	if cerr := d.db.Close(); err == nil {
		err = cerr
	}
	return err
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
		d.dirty[u.XUID] = account
	}
	learned := len(d.dirty) > 0
	d.mu.Unlock()
	if learned {
		if err := d.Flush(); err != nil {
			log.Printf("ident: xuid map not saved yet: %v", err) // retried by the next Flush
		}
	}
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

// Flush writes the XUIDs learned since the last successful flush.
func (d *Directory) Flush() error {
	d.mu.Lock()
	pending := make(map[uint64]string, len(d.dirty))
	for k, v := range d.dirty {
		pending[k] = v
	}
	d.mu.Unlock()
	for x, acct := range pending {
		if _, err := d.db.Exec(`INSERT INTO xuid_map(xuid,account,created) VALUES(?,?,?)
 ON CONFLICT(xuid) DO UPDATE SET account=excluded.account`, strconv.FormatUint(x, 10), acct, time.Now().Unix()); err != nil {
			return err
		}
		d.mu.Lock()
		if d.dirty[x] == acct {
			delete(d.dirty, x)
		}
		d.mu.Unlock()
	}
	return nil
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

// Erase forgets the account (account erasure): its XUID mapping in memory and in Postgres, and
// the cached user. Idempotent; reports the Postgres rows removed.
func (d *Directory) Erase(account string) (int, error) {
	x := XUIDFor(account)
	d.mu.Lock()
	for k, v := range d.byX {
		if v == account {
			delete(d.byX, k)
		}
	}
	for k, v := range d.dirty {
		if v == account {
			delete(d.dirty, k)
		}
	}
	delete(d.cache, account)
	d.mu.Unlock()
	res, err := d.db.Exec(`DELETE FROM xuid_map WHERE account=? OR xuid=?`, account, strconv.FormatUint(x, 10))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}
