// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"github.com/openpak/xbl/internal/ident"
)

var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// Erase removes everything xbl holds for the account (account erasure, card #120): the XUID
// mapping in Postgres and memory, its presence, MPSD session memberships and handles, pending
// device-code grants and open RTA sockets. Idempotent; reports the entries removed.
func (a *App) Erase(ctx context.Context, account string) (int, error) {
	x := ident.XUIDFor(account)
	n := 0
	if a.Hub != nil {
		n += a.Hub.DropAccount(account)
	}
	if a.MPSD != nil {
		n += a.MPSD.EraseAccount(account, x)
	}
	if a.People != nil {
		n += a.People.ErasePresence(x)
	}
	if a.MSA != nil {
		n += a.MSA.EraseAccount(account)
	}
	rows, err := a.Dir.Erase(account)
	if err != nil {
		return n, err
	}
	n += rows
	a.Log.Info("account erased", "account", account, "rows", n, "service", "xbl")
	return n, nil
}

// eraseHandler serves DELETE /internal/accounts/{account_id}/data (bearer ACCOUNT_ERASE_KEY) and
// hands every other request to next. An empty key answers 503: never open.
func eraseHandler(key string, erase func(context.Context, string) (int, error), next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rest, ok := strings.CutPrefix(r.URL.Path, "/internal/accounts/")
		id, tail, _ := strings.Cut(rest, "/")
		if !ok || tail != "data" || r.Method != http.MethodDelete {
			next.ServeHTTP(w, r)
			return
		}
		if key == "" {
			http.Error(w, "erase disabled", http.StatusServiceUnavailable)
			return
		}
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(key)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !uuidRE.MatchString(id) {
			http.Error(w, "invalid account id", http.StatusBadRequest)
			return
		}
		n, err := erase(r.Context(), strings.ToLower(id))
		if err != nil {
			http.Error(w, "erase failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"service": "xbl", "rows": n})
	})
}
