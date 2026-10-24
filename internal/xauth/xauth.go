// Package xauth issues the Xbox token chain a modern client (XAL) asks for:
// device token, title and user tokens, the SISU combined authorization and
// XSTS tokens for any relying party, and the NSAL documents that tell the
// client which relying party a host needs. It also authenticates the
// "XBL3.0 x=<uhs>;<token>" header on every other service call.
//
// Request and response shapes are the public ones (the services' own
// documentation and open-source clients of them); the tokens are xbl's own.
package xauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/openpak/xbl/internal/ident"
	"github.com/openpak/xbl/internal/token"
)

// Lifetimes.
const (
	deviceTTL = 14 * 24 * time.Hour
	userTTL   = 14 * 24 * time.Hour
	xstsTTL   = 16 * time.Hour
)

// Directory resolves identities.
type Directory interface {
	ByAccount(ctx context.Context, account string) (*ident.User, error)
}

// Service is the auth hosts' handler.
type Service struct {
	Tokens *token.Signer
	Dir    Directory
	Log    *slog.Logger
	// Titles maps an MSA client id (AppId) to its Xbox title id. XAL checks
	// the title id SISU returns against its own configuration.
	Titles       map[string]string
	DefaultTitle string
}

// ServeHTTP routes by host and path.
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(strings.Split(r.Host, ":")[0])
	path := strings.ToLower(r.URL.Path)
	switch {
	case path == "/device/authenticate":
		s.device(w, r)
	case path == "/title/authenticate":
		s.title(w, r)
	case path == "/user/authenticate":
		s.user(w, r)
	case path == "/authorize" && strings.HasPrefix(host, "sisu."):
		s.sisu(w, r)
	case path == "/xsts/authorize":
		s.xsts(w, r)
	case strings.HasPrefix(host, "title.mgt.") && strings.HasPrefix(path, "/titles/"):
		s.nsal(w, r)
	default:
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
	}
}

func readJSON(r *http.Request, v any) error {
	b, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// Time is the services' timestamp form (seven fractional digits, UTC).
func Time(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.0000000Z") }

type tokenResp struct {
	IssueInstant  string         `json:"IssueInstant"`
	NotAfter      string         `json:"NotAfter"`
	Token         string         `json:"Token"`
	DisplayClaims map[string]any `json:"DisplayClaims"`
}

func resp(tok string, ttl time.Duration, claims map[string]any) tokenResp {
	now := time.Now()
	return tokenResp{IssueInstant: Time(now), NotAfter: Time(now.Add(ttl)), Token: tok, DisplayClaims: claims}
}

type deviceReq struct {
	Properties struct {
		AuthMethod   string
		Id           string
		DeviceType   string
		SerialNumber string
		Version      string
	}
	RelyingParty string
	TokenType    string
}

func (s *Service) device(w http.ResponseWriter, r *http.Request) {
	var req deviceReq
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad request"})
		return
	}
	id := strings.Trim(req.Properties.Id, "{}")
	if id == "" {
		id = "unknown"
	}
	did := deviceID(id)
	tok := s.Tokens.Mint(token.Claims{Kind: token.Device, Device: did}, deviceTTL)
	s.Log.Info("device token", "type", req.Properties.DeviceType, "version", req.Properties.Version)
	writeJSON(w, http.StatusOK, resp(tok, deviceTTL, map[string]any{"xdi": map[string]any{"did": did, "dcs": "0"}}))
}

// deviceID is the "did" claim form: F + 15 hex digits, stable per device id.
func deviceID(id string) string {
	h := uint64(14695981039346656037)
	for i := 0; i < len(id); i++ {
		h ^= uint64(id[i])
		h *= 1099511628211
	}
	return "F" + strings.ToUpper(strconv.FormatUint(h|1<<60, 16))[1:]
}

type rpsReq struct {
	Properties struct {
		AuthMethod  string
		RpsTicket   string
		SiteName    string
		DeviceToken string
	}
	RelyingParty string
}

// msaAccount reads "t=<access>" (or "d=<access>") into an account.
func (s *Service) msaAccount(ticket string) (string, error) {
	_, t, _ := strings.Cut(ticket, "=")
	if t == "" {
		t = ticket
	}
	c, err := s.Tokens.Verify(t, token.MSAAccess)
	if err != nil {
		return "", err
	}
	return c.Account, nil
}

func (s *Service) title(w http.ResponseWriter, r *http.Request) {
	var req rpsReq
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad request"})
		return
	}
	tid := s.DefaultTitle
	tok := s.Tokens.Mint(token.Claims{Kind: token.Title, Title: tid}, userTTL)
	writeJSON(w, http.StatusOK, resp(tok, userTTL, map[string]any{"xti": map[string]any{"tid": tid}}))
}

func (s *Service) user(w http.ResponseWriter, r *http.Request) {
	var req rpsReq
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad request"})
		return
	}
	acct, err := s.msaAccount(req.Properties.RpsTicket)
	if err != nil {
		unauthorized(w, 2148916233)
		return
	}
	tok := s.Tokens.Mint(token.Claims{Kind: token.User, Account: acct}, userTTL)
	writeJSON(w, http.StatusOK, resp(tok, userTTL, map[string]any{"xui": []any{map[string]any{"uhs": s.Tokens.UserHash(acct)}}}))
}

type sisuReq struct {
	AccessToken       string
	AppId             string
	DeviceToken       string
	Sandbox           string
	SiteName          string
	RelyingParty      string
	UseModernGamertag bool
}

func (s *Service) titleFor(appID string) string {
	if t, ok := s.Titles[strings.ToUpper(appID)]; ok {
		return t
	}
	return s.DefaultTitle
}

func (s *Service) sisu(w http.ResponseWriter, r *http.Request) {
	var req sisuReq
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad request"})
		return
	}
	acct, err := s.msaAccount(req.AccessToken)
	if err != nil {
		s.Log.Warn("sisu: msa token rejected", "app", req.AppId)
		unauthorized(w, 2148916233)
		return
	}
	dev, err := s.Tokens.Verify(req.DeviceToken, token.Device)
	if err != nil {
		s.Log.Warn("sisu: device token rejected", "app", req.AppId)
		unauthorized(w, 2148916227)
		return
	}
	u, err := s.Dir.ByAccount(r.Context(), acct)
	if err != nil {
		s.Log.Warn("sisu: account unavailable", "err", err)
		unauthorized(w, 2148916233)
		return
	}
	tid := s.titleFor(req.AppId)
	rp := req.RelyingParty
	if rp == "" {
		rp = "http://xboxlive.com"
	}
	title := s.Tokens.Mint(token.Claims{Kind: token.Title, Title: tid, Device: dev.Device}, userTTL)
	user := s.Tokens.Mint(token.Claims{Kind: token.User, Account: acct}, userTTL)
	xst := s.mintXSTS(u, rp, dev.Device, tid)
	s.Log.Info("sisu authorize", "app", req.AppId, "title", tid, "rp", rp, "xuid", u.XUIDString())
	writeJSON(w, http.StatusOK, map[string]any{
		"DeviceToken":        req.DeviceToken,
		"TitleToken":         resp(title, userTTL, map[string]any{"xti": map[string]any{"tid": tid}}),
		"UserToken":          resp(user, userTTL, map[string]any{"xui": []any{map[string]any{"uhs": s.Tokens.UserHash(acct)}}}),
		"AuthorizationToken": resp(xst, xstsTTL, map[string]any{"xui": []any{s.xui(u)}}),
		"WebPage":            "https://sisu.xboxlive.com/client/v33/default/view/index.html",
		"Sandbox":            "RETAIL",
		"UseModernGamertag":  true,
		"Flow":               "",
	})
}

func (s *Service) mintXSTS(u *ident.User, rp, device, title string) string {
	return s.Tokens.Mint(token.Claims{Kind: token.XSTS, Account: u.AccountID, XUID: u.XUID, RP: rp, Device: device, Title: title}, xstsTTL)
}

// privileges granted to every OpenPak user: everything a title may check
// (multiplayer 254, communications 252, profile viewing 249, add friend 255,
// cross-play 185, voice 205, video 235, user content 247, ...).
const privileges = "184 185 186 187 188 189 190 191 192 193 194 195 196 197 198 199 200 201 202 203 204 205 206 207 208 211 214 215 216 217 220 224 227 228 235 238 245 247 249 252 254 255"

func (s *Service) xui(u *ident.User) map[string]any {
	return map[string]any{
		"gtg": u.Gamertag,
		"xid": u.XUIDString(),
		"uhs": s.Tokens.UserHash(u.AccountID),
		"mgt": u.Gamertag,
		"mgs": "",
		"umg": u.Gamertag,
		"agg": "Adult",
		"usr": "195 234",
		"utr": "190",
		"prv": privileges,
	}
}

type xstsReq struct {
	RelyingParty string
	TokenType    string
	Properties   struct {
		UserTokens  []string
		DeviceToken string
		TitleToken  string
		SandboxId   string
	}
}

func (s *Service) xsts(w http.ResponseWriter, r *http.Request) {
	var req xstsReq
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad request"})
		return
	}
	var device, tid string
	if d, err := s.Tokens.Verify(req.Properties.DeviceToken, token.Device); err == nil {
		device = d.Device
	}
	if t, err := s.Tokens.Verify(req.Properties.TitleToken, token.Title); err == nil {
		tid = t.Title
	}
	if tid == "" {
		tid = s.DefaultTitle
	}
	claims := map[string]any{}
	tok := ""
	if len(req.Properties.UserTokens) > 0 {
		uc, err := s.Tokens.Verify(req.Properties.UserTokens[0], token.User)
		if err != nil {
			s.Log.Warn("xsts: user token rejected", "rp", req.RelyingParty)
			unauthorized(w, 2148916233)
			return
		}
		u, err := s.Dir.ByAccount(r.Context(), uc.Account)
		if err != nil {
			unauthorized(w, 2148916233)
			return
		}
		tok = s.mintXSTS(u, req.RelyingParty, device, tid)
		claims["xui"] = []any{s.xui(u)}
	} else {
		// Device/title-only XSTS (no user).
		tok = s.Tokens.Mint(token.Claims{Kind: token.XSTS, RP: req.RelyingParty, Device: device, Title: tid}, xstsTTL)
	}
	if device != "" {
		claims["xdi"] = map[string]any{"did": device, "dcs": "0"}
	}
	claims["xti"] = map[string]any{"tid": tid}
	s.Log.Info("xsts authorize", "rp", req.RelyingParty, "title", tid)
	writeJSON(w, http.StatusOK, resp(tok, xstsTTL, claims))
}

func unauthorized(w http.ResponseWriter, xerr uint64) {
	w.Header().Set("WWW-Authenticate", "XSTS error")
	writeJSON(w, http.StatusUnauthorized, map[string]any{
		"Identity": "0", "XErr": xerr, "Message": "", "Redirect": "",
	})
}

// Caller is the authenticated user of a service call.
type Caller struct {
	Account string
	XUID    uint64
	RP      string
	Title   string
}

// ErrNoAuth means the request carried no valid XBL3.0 authorization.
var ErrNoAuth = errors.New("xauth: no valid authorization")

// Authenticate reads "XBL3.0 x=<uhs>;<xsts>" (also XBL2.0).
func (s *Service) Authenticate(r *http.Request) (*Caller, error) {
	h := r.Header.Get("Authorization")
	_, rest, ok := strings.Cut(h, "x=")
	if !ok {
		return nil, ErrNoAuth
	}
	uhs, tok, ok := strings.Cut(rest, ";")
	if !ok {
		return nil, ErrNoAuth
	}
	c, err := s.Tokens.Verify(strings.TrimSpace(tok), token.XSTS)
	if err != nil || c.Account == "" || s.Tokens.UserHash(c.Account) != uhs {
		return nil, ErrNoAuth
	}
	return &Caller{Account: c.Account, XUID: c.XUID, RP: c.RP, Title: c.Title}, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
