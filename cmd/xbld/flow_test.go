package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/openpak/xbl/internal/core"
	"github.com/openpak/xbl/internal/ident"
	"github.com/openpak/xbl/internal/msa"
	"github.com/openpak/xbl/internal/token"
	"github.com/openpak/xbl/internal/xauth"
)

type fakeCore struct {
	accounts map[string]*core.Account
	friends  map[string][]string
}

func (f *fakeCore) VerifyPassword(ctx context.Context, email, password string) (*core.Verified, error) {
	if password != "pw" {
		return nil, &core.Error{Code: core.CodeUnauthenticated}
	}
	id := "acct-" + strings.Split(email, "@")[0]
	if f.accounts[id] == nil {
		return nil, &core.Error{Code: core.CodeUnauthenticated}
	}
	return &core.Verified{AccountID: id, Status: core.StatusActive}, nil
}

func (f *fakeCore) VerifySecondFactor(ctx context.Context, accountID, code string) error { return nil }

func (f *fakeCore) GetAccount(ctx context.Context, account string) (*core.Account, error) {
	if a := f.accounts[account]; a != nil {
		return a, nil
	}
	return nil, core.ErrInactive
}

func (f *fakeCore) ListFriends(ctx context.Context, account string) ([]core.Friend, error) {
	var out []core.Friend
	for _, id := range f.friends[account] {
		out = append(out, core.Friend{AccountID: id, DisplayName: f.accounts[id].DisplayName})
	}
	return out, nil
}

func (f *fakeCore) CanDiscover(ctx context.Context, account, other string) (bool, error) {
	for _, id := range f.friends[account] {
		if id == other {
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeCore) GetPresence(ctx context.Context, accounts []string) (map[string]core.Presence, error) {
	return map[string]core.Presence{}, nil
}

func (f *fakeCore) GetAvatar(ctx context.Context, accountID string, size uint32) ([]byte, error) {
	return nil, &core.Error{Code: core.CodeNotFound}
}

func newFake() *fakeCore {
	return &fakeCore{
		accounts: map[string]*core.Account{
			"acct-alice": {ID: "acct-alice", DisplayName: "Alice", Handle: "alice", Country: "GB"},
			"acct-bob":   {ID: "acct-bob", DisplayName: "Bob", Handle: "bob", Country: "GB"},
		},
		friends: map[string][]string{"acct-alice": {"acct-bob"}, "acct-bob": {"acct-alice"}},
	}
}

type testEnv struct {
	t   *testing.T
	srv *httptest.Server
	app *App
}

func newEnv(t *testing.T) *testEnv {
	t.Helper()
	fc := newFake()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	tok := token.NewSigner(bytes.Repeat([]byte{7}, 32))
	dir, err := ident.Open(fc, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	app := &App{Log: log, Tokens: tok, Dir: dir, Core: fc,
		MSA:  msa.New(fc, tok, log, "https://openpak.org/link"),
		Auth: &xauth.Service{Tokens: tok, Dir: dir, Log: log, Titles: map[string]string{"000000004426B87D": "1739375565"}, DefaultTitle: "1739375565"},
	}
	app.init()
	srv := httptest.NewServer(app)
	t.Cleanup(srv.Close)
	return &testEnv{t: t, srv: srv, app: app}
}

// do sends a request with an explicit Host header.
func (e *testEnv) do(method, host, path, ctype string, body []byte, hdr map[string]string) (int, []byte) {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.srv.URL+path, bytes.NewReader(body))
	req.Host = host
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func (e *testEnv) jsonDo(method, host, path string, in any, hdr map[string]string) (int, map[string]any) {
	e.t.Helper()
	var b []byte
	if in != nil {
		b, _ = json.Marshal(in)
	}
	st, out := e.do(method, host, path, "application/json", b, hdr)
	var m map[string]any
	json.Unmarshal(out, &m)
	return st, m
}

// signIn runs the console flow for one user and returns the XBL3.0 header.
func (e *testEnv) signIn(user string) (string, map[string]any) {
	t := e.t
	form := url.Values{"client_id": {"000000004426B87D"}, "scope": {"service::user.auth.xboxlive.com::MBI_SSL"}, "response_type": {"device_code"}}
	st, b := e.do("POST", "login.live.com", "/oauth20_connect.srf", "application/x-www-form-urlencoded", []byte(form.Encode()), nil)
	if st != 200 {
		t.Fatalf("connect: %d %s", st, b)
	}
	var dc map[string]any
	json.Unmarshal(b, &dc)
	poll := url.Values{"client_id": {"000000004426B87D"}, "grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {dc["device_code"].(string)}}
	st, b = e.do("POST", "login.live.com", "/oauth20_token.srf", "application/x-www-form-urlencoded", []byte(poll.Encode()), nil)
	if st != 400 || !strings.Contains(string(b), "authorization_pending") {
		t.Fatalf("pending poll: %d %s", st, b)
	}
	approve := url.Values{"code": {dc["user_code"].(string)}, "email": {user + "@openpak.org"}, "password": {"pw"}}
	st, b = e.do("POST", "openpak.org", "/link", "application/x-www-form-urlencoded", []byte(approve.Encode()), nil)
	if st != 200 || !strings.Contains(string(b), "Done.") {
		t.Fatalf("approve: %d %s", st, b)
	}
	st, b = e.do("POST", "login.live.com", "/oauth20_token.srf", "application/x-www-form-urlencoded", []byte(poll.Encode()), nil)
	if st != 200 {
		t.Fatalf("token: %d %s", st, b)
	}
	var tk map[string]any
	json.Unmarshal(b, &tk)
	st, dev := e.jsonDo("POST", "device.auth.xboxlive.com", "/device/authenticate", map[string]any{
		"Properties":   map[string]any{"AuthMethod": "ProofOfPossession", "Id": "{0f6c-" + user + "}", "DeviceType": "Nintendo", "Version": "0.0.0"},
		"RelyingParty": "http://auth.xboxlive.com", "TokenType": "JWT"}, nil)
	if st != 200 {
		t.Fatalf("device: %d", st)
	}
	st, sisu := e.jsonDo("POST", "sisu.xboxlive.com", "/authorize", map[string]any{
		"AccessToken": "t=" + tk["access_token"].(string), "AppId": "000000004426B87D", "DeviceToken": dev["Token"],
		"Sandbox": "RETAIL", "SiteName": "user.auth.xboxlive.com", "UseModernGamertag": true}, nil)
	if st != 200 {
		t.Fatalf("sisu: %d %v", st, sisu)
	}
	az := sisu["AuthorizationToken"].(map[string]any)
	xui := az["DisplayClaims"].(map[string]any)["xui"].([]any)[0].(map[string]any)
	return "XBL3.0 x=" + xui["uhs"].(string) + ";" + az["Token"].(string), sisu
}

func TestSignInChain(t *testing.T) {
	e := newEnv(t)
	authz, sisu := e.signIn("alice")
	tt := sisu["TitleToken"].(map[string]any)["DisplayClaims"].(map[string]any)["xti"].(map[string]any)
	if tt["tid"] != "1739375565" {
		t.Fatalf("title id %v", tt["tid"])
	}
	xui := sisu["AuthorizationToken"].(map[string]any)["DisplayClaims"].(map[string]any)["xui"].([]any)[0].(map[string]any)
	if xui["gtg"] != "alice" || xui["xid"] != ident.XUIDForString("acct-alice") {
		t.Fatalf("claims %v", xui)
	}
	// XSTS for another relying party from the SISU user token.
	ut := sisu["UserToken"].(map[string]any)["Token"]
	st, x := e.jsonDo("POST", "xsts.auth.xboxlive.com", "/xsts/authorize", map[string]any{
		"RelyingParty": "rp://api.minecraftservices.com/", "TokenType": "JWT",
		"Properties": map[string]any{"UserTokens": []any{ut}, "SandboxId": "RETAIL"}}, nil)
	if st != 200 || x["Token"] == nil {
		t.Fatalf("xsts: %d %v", st, x)
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", authz)
	c, err := e.app.Auth.Authenticate(req)
	if err != nil || c.Account != "acct-alice" {
		t.Fatalf("authenticate: %v %v", c, err)
	}
	req.Header.Set("Authorization", "XBL3.0 x=123;"+x["Token"].(string))
	if _, err := e.app.Auth.Authenticate(req); err == nil {
		t.Fatal("wrong uhs accepted")
	}
	// NSAL.
	st, n := e.jsonDo("GET", "title.mgt.xboxlive.com", "/titles/default/endpoints?type=1", nil, nil)
	if st != 200 || len(n["EndPoints"].([]any)) == 0 {
		t.Fatalf("nsal: %d %v", st, n)
	}
}

func TestBadPasswordAndRefresh(t *testing.T) {
	e := newEnv(t)
	form := url.Values{"client_id": {"x"}, "scope": {"s"}, "response_type": {"device_code"}}
	_, b := e.do("POST", "login.live.com", "/oauth20_connect.srf", "application/x-www-form-urlencoded", []byte(form.Encode()), nil)
	var dc map[string]any
	json.Unmarshal(b, &dc)
	approve := url.Values{"code": {dc["user_code"].(string)}, "email": {"alice@openpak.org"}, "password": {"nope"}}
	_, page := e.do("POST", "openpak.org", "/link", "application/x-www-form-urlencoded", []byte(approve.Encode()), nil)
	if !strings.Contains(string(page), "do not match") {
		t.Fatalf("bad password page: %s", page)
	}
	refresh := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"garbage"}}
	st, _ := e.do("POST", "login.live.com", "/oauth20_token.srf", "application/x-www-form-urlencoded", []byte(refresh.Encode()), nil)
	if st != 400 {
		t.Fatalf("garbage refresh: %d", st)
	}
	good := e.app.Tokens.Mint(token.Claims{Kind: token.MSARefresh, Account: "acct-alice", Scope: "s"}, 3600e9)
	refresh.Set("refresh_token", good)
	st, b = e.do("POST", "login.live.com", "/oauth20_token.srf", "application/x-www-form-urlencoded", []byte(refresh.Encode()), nil)
	if st != 200 || !strings.Contains(string(b), "access_token") {
		t.Fatalf("refresh: %d %s", st, b)
	}
}

func TestInternalApprove(t *testing.T) {
	e := newEnv(t)
	in := httptest.NewServer(e.app.MSA.Internal("k3y"))
	defer in.Close()
	form := url.Values{"client_id": {"000000004426B87D"}, "scope": {"s"}, "response_type": {"device_code"}}
	_, b := e.do("POST", "login.live.com", "/oauth20_connect.srf", "application/x-www-form-urlencoded", []byte(form.Encode()), nil)
	var dc map[string]any
	json.Unmarshal(b, &dc)
	code := dc["user_code"].(string)
	call := func(method, path, key, body string) (int, map[string]any) {
		req, _ := http.NewRequest(method, in.URL+path, strings.NewReader(body))
		if key != "" {
			req.Header.Set("X-Internal-Key", key)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]any
		json.NewDecoder(resp.Body).Decode(&m)
		return resp.StatusCode, m
	}
	if st, _ := call("GET", "/internal/v1/link/"+code, "wrong", ""); st != 401 {
		t.Fatalf("wrong key %d", st)
	}
	if st, m := call("GET", "/internal/v1/link/"+strings.ToLower(code[:4])+"-"+code[4:], "k3y", ""); st != 200 || m["client_id"] != "000000004426B87D" {
		t.Fatalf("lookup %d %v", st, m)
	}
	if st, _ := call("POST", "/internal/v1/link/approve", "k3y", `{"user_code":"`+code+`","account_id":"acct-nobody"}`); st != 403 {
		t.Fatalf("inactive account %d", st)
	}
	if st, m := call("POST", "/internal/v1/link/approve", "k3y", `{"user_code":"`+code+`","account_id":"acct-bob"}`); st != 200 || m["gamertag"] != "bob" {
		t.Fatalf("approve %d %v", st, m)
	}
	if st, _ := call("POST", "/internal/v1/link/approve", "k3y", `{"user_code":"`+code+`","account_id":"acct-bob"}`); st != 404 {
		t.Fatalf("second approve %d", st)
	}
	poll := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {dc["device_code"].(string)}}
	if st, b := e.do("POST", "login.live.com", "/oauth20_token.srf", "application/x-www-form-urlencoded", []byte(poll.Encode()), nil); st != 200 {
		t.Fatalf("token after internal approve %d %s", st, b)
	}
}
