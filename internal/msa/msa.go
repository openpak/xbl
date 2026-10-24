// Package msa answers the Microsoft account endpoints a console's XAL uses at
// login.live.com: the remote-connect (device code) flow and refresh, plus the
// OpenPak page where a person approves a console's code with their OpenPak
// email and password.
//
// Flow (public OAuth 2.0 device authorization, RFC 8628, in MSA's dialect):
//
//	POST /oauth20_connect.srf  client_id, scope, response_type=device_code
//	  -> {user_code, device_code, verification_uri, expires_in, interval}
//	POST /oauth20_token.srf    grant_type=urn:ietf:params:oauth:grant-type:device_code
//	  -> 400 {"error":"authorization_pending"} until approved, then tokens
//	POST /oauth20_token.srf    grant_type=refresh_token, refresh_token, scope
package msa

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/openpak/xbl/internal/core"
	"github.com/openpak/xbl/internal/ident"
	"github.com/openpak/xbl/internal/token"
)

// Lifetimes.
const (
	codeTTL    = 15 * time.Minute
	pollEvery  = 5 // seconds
	accessTTL  = 24 * time.Hour
	refreshTTL = 90 * 24 * time.Hour
)

// Core is the account-core surface the approval page needs.
type Core interface {
	VerifyPassword(ctx context.Context, email, password string) (*core.Verified, error)
	VerifySecondFactor(ctx context.Context, accountID, code string) error
	GetAccount(ctx context.Context, account string) (*core.Account, error)
}

// Service is the login.live.com handler.
type Service struct {
	Core    Core
	Tokens  *token.Signer
	Log     *slog.Logger
	LinkURL string // shown to the console as verification_uri

	mu      sync.Mutex
	pending map[string]*grant // device_code -> grant
	byUser  map[string]string // user_code -> device_code
}

type grant struct {
	userCode, clientID, scope string
	exp                       time.Time
	account                   string
}

// New builds the service.
func New(c Core, t *token.Signer, log *slog.Logger, linkURL string) *Service {
	return &Service{Core: c, Tokens: t, Log: log, LinkURL: linkURL, pending: map[string]*grant{}, byUser: map[string]string{}}
}

// ServeHTTP routes by path.
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch strings.ToLower(r.URL.Path) {
	case "/oauth20_connect.srf":
		s.connect(w, r)
	case "/oauth20_token.srf":
		s.token(w, r)
	case "/oauth20_logout.srf", "/oauth20_desktop.srf":
		w.WriteHeader(http.StatusOK)
	case "/link", "/link/", "/xbox/link", "/xbox/link/":
		s.link(w, r)
	default:
		http.NotFound(w, r)
	}
}

const codeAlphabet = "BCDFGHJKLMNPQRSTVWXZ23456789" // no vowels, no 0/1: no words, no lookalikes

func randomString(alphabet string, n int) string {
	b := make([]byte, n)
	rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

func (s *Service) connect(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "bad form")
		return
	}
	if r.Form.Get("response_type") != "device_code" {
		oauthError(w, http.StatusBadRequest, "unsupported_response_type", "only device_code is supported")
		return
	}
	g := &grant{clientID: r.Form.Get("client_id"), scope: r.Form.Get("scope"), exp: time.Now().Add(codeTTL)}
	device := randomString("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 40)
	s.mu.Lock()
	s.gc()
	for {
		g.userCode = randomString(codeAlphabet, 8)
		if _, taken := s.byUser[g.userCode]; !taken {
			break
		}
	}
	s.pending[device] = g
	s.byUser[g.userCode] = device
	s.mu.Unlock()
	s.Log.Info("msa device code issued", "client", g.clientID, "scope", g.scope)
	writeJSON(w, http.StatusOK, map[string]any{
		"user_code":        g.userCode,
		"device_code":      device,
		"verification_uri": s.LinkURL,
		"expires_in":       int(codeTTL.Seconds()),
		"interval":         pollEvery,
	})
}

func (s *Service) gc() {
	now := time.Now()
	for d, g := range s.pending {
		if now.After(g.exp) {
			delete(s.byUser, g.userCode)
			delete(s.pending, d)
		}
	}
}

func (s *Service) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "bad form")
		return
	}
	switch gt := r.Form.Get("grant_type"); gt {
	case "urn:ietf:params:oauth:grant-type:device_code", "device_code":
		dc := r.Form.Get("device_code")
		s.mu.Lock()
		g, ok := s.pending[dc]
		if ok && time.Now().After(g.exp) {
			delete(s.byUser, g.userCode)
			delete(s.pending, dc)
			ok = false
		}
		var acct string
		if ok && g.account != "" {
			acct = g.account
			delete(s.byUser, g.userCode)
			delete(s.pending, dc)
		}
		s.mu.Unlock()
		switch {
		case !ok:
			oauthError(w, http.StatusBadRequest, "expired_token", "The device code has expired or is unknown.")
		case acct == "":
			oauthError(w, http.StatusBadRequest, "authorization_pending", "The user has not yet approved this code.")
		default:
			s.Log.Info("msa device code redeemed", "client", g.clientID)
			s.issue(w, acct, g.scope)
		}
	case "refresh_token":
		c, err := s.Tokens.Verify(r.Form.Get("refresh_token"), token.MSARefresh)
		if err != nil {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "The refresh token is invalid or expired.")
			return
		}
		if _, err := s.Core.GetAccount(r.Context(), c.Account); err != nil {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "The account is not available.")
			return
		}
		scope := r.Form.Get("scope")
		if scope == "" {
			scope = c.Scope
		}
		s.issue(w, c.Account, scope)
	default:
		s.Log.Warn("msa unsupported grant", "grant_type", gt)
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant_type")
	}
}

func (s *Service) issue(w http.ResponseWriter, account, scope string) {
	writeJSON(w, http.StatusOK, map[string]any{
		"token_type":    "bearer",
		"expires_in":    int(accessTTL.Seconds()),
		"scope":         scope,
		"access_token":  s.Tokens.Mint(token.Claims{Kind: token.MSAAccess, Account: account, Scope: scope}, accessTTL),
		"refresh_token": s.Tokens.Mint(token.Claims{Kind: token.MSARefresh, Account: account, Scope: scope}, refreshTTL),
		"user_id":       fmt.Sprintf("%016x", ident.XUIDFor(account)),
	})
}

// Approve marks a user code as approved by account (used by the page).
func (s *Service) Approve(userCode, account string) bool {
	userCode = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(userCode), "-", ""))
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.byUser[userCode]
	if !ok {
		return false
	}
	g := s.pending[d]
	if g == nil || time.Now().After(g.exp) || g.account != "" {
		return false
	}
	g.account = account
	return true
}

// Pending describes a code that is waiting for approval.
type Pending struct {
	UserCode  string    `json:"user_code"`
	ClientID  string    `json:"client_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Lookup reports a pending, unapproved code (normalised as Approve does).
func (s *Service) Lookup(userCode string) (*Pending, bool) {
	userCode = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(userCode), "-", ""))
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.byUser[userCode]
	if !ok {
		return nil, false
	}
	g := s.pending[d]
	if g == nil || time.Now().After(g.exp) || g.account != "" {
		return nil, false
	}
	return &Pending{UserCode: g.userCode, ClientID: g.clientID, ExpiresAt: g.exp.UTC()}, true
}

// Internal is the approval API for a trusted front that has already
// signed the person in (the website's /link page). It must only be served
// on a private listener, and every call needs the internal key:
//
//	GET  /internal/v1/link/{user_code}            200 {user_code, client_id, expires_at} | 404
//	POST /internal/v1/link/approve {"user_code","account_id"}
//	                                               200 {"approved":true,"gamertag"} | 404 | 403 | 400
func (s *Service) Internal(key string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if key == "" || !hmacEqual(r.Header.Get("X-Internal-Key"), key) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		p := r.URL.Path
		switch {
		case r.Method == http.MethodPost && p == "/internal/v1/link/approve":
			var req struct {
				UserCode  string `json:"user_code"`
				AccountID string `json:"account_id"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil || req.UserCode == "" || req.AccountID == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user_code and account_id are required"})
				return
			}
			a, err := s.Core.GetAccount(r.Context(), req.AccountID)
			if err != nil {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "account_not_active"})
				return
			}
			if !s.Approve(req.UserCode, req.AccountID) {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "code_not_found_or_expired"})
				return
			}
			s.Log.Info("msa device code approved", "via", "internal")
			writeJSON(w, http.StatusOK, map[string]any{"approved": true, "gamertag": ident.Gamertag(a)})
		case r.Method == http.MethodGet && strings.HasPrefix(p, "/internal/v1/link/"):
			pd, ok := s.Lookup(strings.TrimPrefix(p, "/internal/v1/link/"))
			if !ok {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "code_not_found_or_expired"})
				return
			}
			writeJSON(w, http.StatusOK, pd)
		default:
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
		}
	})
}

func hmacEqual(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

var page = template.Must(template.New("link").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>OpenPak - link a console</title>
<style>body{font-family:system-ui,sans-serif;max-width:28rem;margin:3rem auto;padding:0 1rem;color:#111}
input{display:block;width:100%;box-sizing:border-box;padding:.6rem;margin:.3rem 0 1rem;font-size:1rem}
button{padding:.7rem 1.4rem;font-size:1rem}.msg{padding:.8rem;border-radius:.4rem;background:#eef}.err{background:#fee}</style></head>
<body><h1>Link a console</h1>
{{if .Done}}<p class="msg">Done. Your console is signing in as <b>{{.Gamertag}}</b>. You can close this page.</p>
{{else}}<p>Enter the code your game shows, then sign in with your OpenPak account.</p>
{{if .Error}}<p class="msg err">{{.Error}}</p>{{end}}
<form method="post">
<label>Code<input name="code" value="{{.Code}}" autocomplete="off" autocapitalize="characters" required></label>
<label>OpenPak email<input name="email" type="email" value="{{.Email}}" autocomplete="username" required></label>
<label>Password<input name="password" type="password" autocomplete="current-password" required></label>
{{if .NeedOTP}}<label>Two-factor code<input name="otp" inputmode="numeric" autocomplete="one-time-code" required></label>{{end}}
<button type="submit">Link</button></form>{{end}}
</body></html>`))

type pageData struct {
	Code, Email, Error, Gamertag string
	NeedOTP, Done                bool
}

func (s *Service) link(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'")
	w.Header().Set("X-Frame-Options", "DENY")
	if r.Method != http.MethodPost {
		page.Execute(w, pageData{Code: r.URL.Query().Get("otc")})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	d := pageData{Code: r.PostForm.Get("code"), Email: r.PostForm.Get("email")}
	v, err := s.Core.VerifyPassword(r.Context(), d.Email, r.PostForm.Get("password"))
	switch {
	case core.IsCode(err, core.CodeUnauthenticated):
		d.Error = "That email and password do not match an OpenPak account."
	case err != nil:
		s.Log.Error("link: verify password", "err", err)
		d.Error = "OpenPak accounts are unavailable right now. Try again in a minute."
	case v.AccountID == "" || v.Status != core.StatusActive:
		d.Error = "This account cannot sign in."
	}
	if d.Error == "" && v.TwoFactorRequired {
		otp := strings.TrimSpace(r.PostForm.Get("otp"))
		if otp == "" {
			d.NeedOTP, d.Error = true, "Enter your two-factor code."
		} else if err := s.Core.VerifySecondFactor(r.Context(), v.AccountID, otp); err != nil {
			d.NeedOTP, d.Error = true, "That two-factor code is not right."
		}
	}
	if d.Error == "" && !s.Approve(d.Code, v.AccountID) {
		d.Error = "That code is not valid any more. Start the sign-in on your console again."
	}
	if d.Error != "" {
		w.WriteHeader(http.StatusOK)
		page.Execute(w, d)
		return
	}
	if a, err := s.Core.GetAccount(r.Context(), v.AccountID); err == nil {
		d.Gamertag = ident.Gamertag(a)
	}
	d.Done = true
	s.Log.Info("msa device code approved")
	page.Execute(w, d)
}

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
