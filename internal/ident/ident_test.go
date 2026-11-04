// SPDX-License-Identifier: AGPL-3.0-only

package ident

import (
	"context"
	"testing"

	"github.com/openpak/xbl/internal/core"
	"github.com/openpak/xbl/internal/pgdb"
)

type fakeCore struct{}

func (fakeCore) GetAccount(ctx context.Context, id string) (*core.Account, error) {
	return &core.Account{ID: id, Handle: "Handle-" + id}, nil
}

// An XUID handed out before a restart resolves again afterwards.
func TestXUIDMapSurvivesRestart(t *testing.T) {
	dsn := pgdb.TestDSN(t)
	ctx := context.Background()
	d1, err := Open(fakeCore{}, dsn)
	if err != nil {
		t.Fatal(err)
	}
	u, err := d1.ByAccount(ctx, "acct-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := d1.Close(); err != nil {
		t.Fatal(err)
	}
	d2, err := Open(fakeCore{}, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer d2.Close()
	got, err := d2.ByXUID(ctx, u.XUID)
	if err != nil || got.AccountID != "acct-1" || got.XUID != u.XUID {
		t.Fatalf("after restart: %+v %v", got, err)
	}
	if _, err := d2.ByXUID(ctx, 12345); err != ErrUnknown {
		t.Fatalf("unknown xuid: %v", err)
	}
}

// Erase drops one account's mapping and leaves the others; a second run removes nothing.
func TestEraseRemovesOnlyThatAccount(t *testing.T) {
	dsn := pgdb.TestDSN(t)
	ctx := context.Background()
	d, err := Open(fakeCore{}, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	a, _ := d.ByAccount(ctx, "acct-a")
	b, _ := d.ByAccount(ctx, "acct-b")
	if err := d.Flush(); err != nil {
		t.Fatal(err)
	}
	if n, err := d.Erase("acct-a"); err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if _, err := d.ByXUID(ctx, a.XUID); err != ErrUnknown {
		t.Fatalf("erased xuid still resolves: %v", err)
	}
	if got, err := d.ByXUID(ctx, b.XUID); err != nil || got.AccountID != "acct-b" {
		t.Fatalf("other account touched: %v", err)
	}
	if n, err := d.Erase("acct-a"); err != nil || n != 0 {
		t.Fatalf("second run n=%d err=%v", n, err)
	}
}
