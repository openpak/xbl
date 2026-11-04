// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const eraseAcct = "11111111-1111-4111-8111-111111111111"

func TestEraseEndpointGuards(t *testing.T) {
	calls := 0
	erase := func(_ context.Context, id string) (int, error) { calls++; return 4, nil }
	passed := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { passed = true })
	do := func(h http.Handler, method, path, auth string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, nil)
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	h := eraseHandler("k", erase, next)
	p := "/internal/accounts/" + eraseAcct + "/data"
	for _, c := range []struct {
		auth string
		path string
		code int
	}{{"", p, 401}, {"Bearer x", p, 401}, {"Bearer k", "/internal/accounts/nope/data", 400}} {
		if w := do(h, "DELETE", c.path, c.auth); w.Code != c.code {
			t.Fatalf("%+v -> %d", c, w.Code)
		}
	}
	if w := do(eraseHandler("", erase, next), "DELETE", p, "Bearer "); w.Code != 503 {
		t.Fatalf("unset key -> %d", w.Code)
	}
	if calls != 0 {
		t.Fatal("erase ran unauthorised")
	}
	w := do(h, "DELETE", p, "Bearer k")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"service":"xbl"`) || !strings.Contains(w.Body.String(), `"rows":4`) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	do(h, "POST", "/internal/v1/link/approve", "")
	if !passed {
		t.Fatal("other internal routes not passed through")
	}
}
