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
