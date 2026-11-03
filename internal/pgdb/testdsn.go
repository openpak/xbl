// SPDX-License-Identifier: AGPL-3.0-only

package pgdb

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TempDSN returns a DSN for a fresh private schema of the Postgres at base and
// a function that drops it. Calling Open twice with the same DSN models a restart.
func TempDSN(base string) (dsn string, drop func(), err error) {
	var b [6]byte
	rand.Read(b[:])
	schema := "t_" + hex.EncodeToString(b[:])
	u, err := url.Parse(base)
	if err != nil {
		return "", nil, errors.New("pgdb: bad base DSN")
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	drop = func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cfg, err := pgx.ParseConfig(base)
		if err != nil {
			return
		}
		c, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			return
		}
		defer c.Close(ctx)
		c.Exec(ctx, `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
	}
	return u.String(), drop, nil
}

// TestDSN is TempDSN for tests, using the Postgres named by XBL_TEST_DATABASE_URL;
// the test is skipped when the variable is unset.
func TestDSN(t testing.TB) string {
	t.Helper()
	base := os.Getenv("XBL_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("XBL_TEST_DATABASE_URL not set")
	}
	dsn, drop, err := TempDSN(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(drop)
	return dsn
}
