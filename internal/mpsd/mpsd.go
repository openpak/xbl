// Package mpsd is the Multiplayer Session Directory
// (sessiondirectory.xboxlive.com, contract 107): session documents keyed by
// service config, template and name, member join/leave through the "me" key,
// handles (activity, invite, transfer), the activity query, and shoulder taps
// over RTA when a session changes.
//
// Sessions live in memory: they are short-lived lobbies and games, and a
// restart ends them the way a lost connection would.
package mpsd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openpak/xbl/internal/ident"
	"github.com/openpak/xbl/internal/rta"
)

// Caller is the authenticated user.
type Caller struct {
	Account string
	XUID    uint64
	Title   string
}

// Directory resolves identities.
type Directory interface {
	ByAccount(ctx context.Context, account string) (*ident.User, error)
	ByXUID(ctx context.Context, xuid uint64) (*ident.User, error)
}

// Friends lists an account's friends (for the social activity query).
type Friends func(ctx context.Context, account string) ([]string, error)

// Service is the session directory.
type Service struct {
	Auth    func(r *http.Request) (*Caller, error)
	Dir     Directory
	Friends Friends
	Hub     *rta.Hub
	Log     *slog.Logger
	// MaxMembers is the template default when a session is created without
	// constants (Multiplayer Manager never sends them).
	MaxMembers int

	mu       sync.Mutex
	sessions map[string]*Session
	handles  map[string]*Handle
}

// Ref names a session.
type Ref struct {
	SCID     string `json:"scid"`
	Template string `json:"templateName"`
	Name     string `json:"name"`
}

func (r Ref) key() string {
	return strings.ToLower(r.SCID) + "~" + strings.ToLower(r.Template) + "~" + strings.ToLower(r.Name)
}

func (r Ref) path() string {
	return "/serviceconfigs/" + r.SCID + "/sessiontemplates/" + r.Template + "/sessions/" + r.Name
}

// Session is one session document.
type Session struct {
	Ref           Ref
	Constants     map[string]any
	System        map[string]any // properties.system
	Custom        map[string]any // properties.custom
	Servers       map[string]any
	RoleTypes     map[string]any
	Members       []*Member
	NextIndex     int
	ChangeNumber  int64
	Branch        string
	CorrelationID string
	StartTime     time.Time
}

// Member is one session member.
type Member struct {
	Index         int
	XUID          uint64
	Account       string
	Gamertag      string
	Constants     map[string]any // constants (system + custom)
	System        map[string]any // properties.system
	Custom        map[string]any // properties.custom
	Roles         map[string]any
	Reserved      bool
	JoinTime      time.Time
	ActiveTitleID string
	Connection    string // RTA connection id, from properties.system.connection
}

// Handle is an MPSD handle.
type Handle struct {
	ID         string
	Type       string // activity | invite | transfer
	Ref        Ref
	Origin     *Ref
	OwnerXUID  uint64
	Invited    uint64
	TitleID    string
	Context    string
	ContextStr string
	Expiration time.Time
	Created    time.Time
}

func (s *Service) init() {
	if s.sessions == nil {
		s.sessions = map[string]*Session{}
		s.handles = map[string]*Handle{}
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if v != nil {
		json.NewEncoder(w).Encode(v)
	}
}

func errJSON(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"code": status, "message": msg})
}

// ServeHTTP routes the MPSD paths (case-insensitive).
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c, err := s.Auth(r)
	if err != nil {
		errJSON(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	low := make([]string, len(parts))
	for i, p := range parts {
		low[i] = strings.ToLower(p)
	}
	switch {
	case len(low) == 6 && low[0] == "serviceconfigs" && low[2] == "sessiontemplates" && low[4] == "sessions":
		ref := Ref{SCID: parts[1], Template: parts[3], Name: parts[5]}
		switch r.Method {
		case http.MethodPut:
			s.put(w, r, c, ref, false)
		case http.MethodGet:
			s.get(w, r, c, ref, false)
		default:
			errJSON(w, http.StatusMethodNotAllowed, "method")
		}
	case (len(low) >= 3 && low[0] == "serviceconfigs" && low[len(low)-1] == "sessions") ||
		(len(low) >= 3 && low[0] == "serviceconfigs" && low[len(low)-1] == "batch"):
		s.browse(w, r, c, parts)
	case len(low) == 1 && low[0] == "handles" && r.Method == http.MethodPost:
		s.postHandle(w, r, c)
	case len(low) == 2 && low[0] == "handles" && low[1] == "query" && r.Method == http.MethodPost:
		s.queryHandles(w, r, c)
	case len(low) == 2 && low[0] == "handles":
		s.handle(w, r, c, parts[1])
	case len(low) == 3 && low[0] == "handles" && low[2] == "session":
		s.mu.Lock()
		s.init()
		h := s.handles[strings.ToLower(parts[1])]
		s.mu.Unlock()
		if h == nil {
			errJSON(w, http.StatusNotFound, "handle not found")
			return
		}
		switch r.Method {
		case http.MethodPut:
			s.put(w, r, c, h.Ref, true)
		case http.MethodGet:
			s.get(w, r, c, h.Ref, true)
		default:
			errJSON(w, http.StatusMethodNotAllowed, "method")
		}
	default:
		s.Log.Warn("mpsd: unhandled", "method", r.Method, "path", r.URL.Path)
		errJSON(w, http.StatusNotFound, "not found")
	}
}

func readBody(r *http.Request) (map[string]any, error) {
	b, err := io.ReadAll(io.LimitReader(r.Body, 256<<10))
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return map[string]any{}, nil
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func obj(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// merge applies a JSON merge (null deletes) of src into dst.
func merge(dst, src map[string]any) map[string]any {
	if dst == nil {
		dst = map[string]any{}
	}
	for k, v := range src {
		if v == nil {
			delete(dst, k)
			continue
		}
		if sm, ok := v.(map[string]any); ok {
			if dm, ok := dst[k].(map[string]any); ok {
				dst[k] = merge(dm, sm)
				continue
			}
			dst[k] = merge(nil, sm)
			continue
		}
		dst[k] = v
	}
	return dst
}

func (s *Service) etag(sess *Session) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", sess.Branch, sess.ChangeNumber)))
	return `"` + hex.EncodeToString(h[:8]) + `"`
}

func (s *Service) put(w http.ResponseWriter, r *http.Request, c *Caller, ref Ref, byHandle bool) {
	body, err := readBody(r)
	if err != nil {
		errJSON(w, http.StatusBadRequest, "bad json")
		return
	}
	me, err := s.Dir.ByAccount(r.Context(), c.Account)
	if err != nil {
		errJSON(w, http.StatusForbidden, "account unavailable")
		return
	}
	ifMatch, ifNone := r.Header.Get("If-Match"), r.Header.Get("If-None-Match")
	s.mu.Lock()
	s.init()
	sess := s.sessions[ref.key()]
	switch {
	case sess == nil && (ifMatch != "" || byHandle):
		s.mu.Unlock()
		errJSON(w, http.StatusNotFound, "session not found")
		return
	case sess != nil && ifNone == "*":
		out, tag := s.render(sess, c.XUID), s.etag(sess)
		s.mu.Unlock()
		s.reply(w, http.StatusPreconditionFailed, sess.Ref, out, tag)
		return
	case sess != nil && ifMatch != "" && ifMatch != "*" && strings.Trim(ifMatch, `"`) != strings.Trim(s.etag(sess), `"`):
		out, tag := s.render(sess, c.XUID), s.etag(sess)
		s.mu.Unlock()
		s.reply(w, http.StatusPreconditionFailed, sess.Ref, out, tag)
		return
	}
	created := false
	if sess == nil {
		created = true
		sess = &Session{Ref: ref, Constants: s.defaultConstants(), System: map[string]any{}, Custom: map[string]any{},
			Branch: rta.NewID(), CorrelationID: rta.NewID(), StartTime: time.Now().UTC()}
		if cons := obj(body["constants"]); cons != nil {
			sess.Constants = merge(sess.Constants, cons)
		}
		s.sessions[ref.key()] = sess
	}
	if props := obj(body["properties"]); props != nil {
		if sys := obj(props["system"]); sys != nil {
			sess.System = merge(sess.System, sys)
		}
		if cus := obj(props["custom"]); cus != nil {
			sess.Custom = merge(sess.Custom, cus)
		}
	}
	if sv := obj(body["servers"]); sv != nil {
		sess.Servers = merge(sess.Servers, sv)
	}
	if rt := obj(body["roleTypes"]); rt != nil {
		sess.RoleTypes = merge(sess.RoleTypes, rt)
	}
	full := false
	if members, ok := body["members"].(map[string]any); ok {
		for key, v := range members {
			if key == "me" {
				if v == nil {
					s.removeMember(sess, c.XUID)
					continue
				}
				if !s.upsertMember(sess, me, obj(v), false, c.Title) {
					full = true
				}
				continue
			}
			if strings.HasPrefix(key, "reserve_") && v != nil {
				mo := obj(v)
				xs, _ := obj(obj(mo["constants"])["system"])["xuid"].(string)
				x, err := strconv.ParseUint(xs, 10, 64)
				if err != nil {
					continue
				}
				u, err := s.Dir.ByXUID(r.Context(), x)
				if err != nil {
					u = &ident.User{XUID: x, Gamertag: ""}
				}
				s.upsertMember(sess, u, mo, true, c.Title)
			}
		}
	}
	if full {
		if created {
			delete(s.sessions, ref.key())
		}
		s.mu.Unlock()
		errJSON(w, http.StatusForbidden, "session is full")
		return
	}
	sess.ChangeNumber++
	if len(sess.Members) == 0 {
		delete(s.sessions, ref.key())
		s.mu.Unlock()
		s.Log.Info("mpsd session ended", "template", ref.Template, "name", ref.Name)
		s.tap(sess, 0)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	out, tag := s.render(sess, c.XUID), s.etag(sess)
	s.mu.Unlock()
	status := http.StatusOK
	if created {
		status = http.StatusCreated
		s.Log.Info("mpsd session created", "template", ref.Template, "name", ref.Name, "by", c.XUID)
	}
	s.reply(w, status, sess.Ref, out, tag)
	s.tap(sess, 0)
}

func (s *Service) defaultConstants() map[string]any {
	max := s.MaxMembers
	if max <= 0 {
		max = 4
	}
	return map[string]any{
		"system": map[string]any{
			"version":         1,
			"maxMembersCount": max,
			"visibility":      "open",
			"capabilities": map[string]any{
				"connectivity":                       true,
				"connectionRequiredForActiveMembers": true,
			},
			"reservedRemovalTimeout": 30000,
			"inactiveRemovalTimeout": 0,
			"readyRemovalTimeout":    180000,
			"sessionEmptyTimeout":    0,
		},
		"custom": map[string]any{},
	}
}

func (s *Service) maxMembers(sess *Session) int {
	if v, ok := obj(sess.Constants["system"])["maxMembersCount"].(float64); ok && v > 0 {
		return int(v)
	}
	if v, ok := obj(sess.Constants["system"])["maxMembersCount"].(int); ok && v > 0 {
		return v
	}
	return 4
}

// upsertMember applies a member write; false means the session is full.
func (s *Service) upsertMember(sess *Session, u *ident.User, mo map[string]any, reserve bool, title string) bool {
	var m *Member
	for _, x := range sess.Members {
		if x.XUID == u.XUID {
			m = x
		}
	}
	if m == nil {
		if len(sess.Members) >= s.maxMembers(sess) {
			return false
		}
		m = &Member{Index: sess.NextIndex, XUID: u.XUID, Account: u.AccountID, Gamertag: u.Gamertag,
			Constants: map[string]any{"system": map[string]any{"xuid": u.XUIDString()}}, System: map[string]any{}, Custom: map[string]any{},
			JoinTime: time.Now().UTC(), ActiveTitleID: title, Reserved: reserve}
		sess.NextIndex++
		sess.Members = append(sess.Members, m)
		if cons := obj(mo["constants"]); cons != nil {
			m.Constants = merge(m.Constants, cons)
			obj(m.Constants["system"])["xuid"] = u.XUIDString()
		}
	}
	if props := obj(mo["properties"]); props != nil {
		if sys := obj(props["system"]); sys != nil {
			m.System = merge(m.System, sys)
			if cn, ok := sys["connection"].(string); ok {
				m.Connection = cn
			}
			if a, ok := sys["active"].(bool); ok && a {
				m.Reserved = false
			}
		}
		if cus := obj(props["custom"]); cus != nil {
			m.Custom = merge(m.Custom, cus)
		}
	}
	if ro := obj(mo["roles"]); ro != nil {
		m.Roles = merge(m.Roles, ro)
	}
	return true
}

func (s *Service) removeMember(sess *Session, xuid uint64) bool {
	for i, m := range sess.Members {
		if m.XUID == xuid {
			sess.Members = append(sess.Members[:i], sess.Members[i+1:]...)
			return true
		}
	}
	return false
}

func deviceToken(xuid uint64) string {
	h := sha256.Sum256([]byte("dt:" + strconv.FormatUint(xuid, 10)))
	return hex.EncodeToString(h[:16])
}

func ts(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.0000000Z") }

// render builds the session document the client parses (see the wire spec):
// numeric member keys chained by "next", membersInfo, constants.system and
// properties.system always present.
func (s *Service) render(sess *Session, caller uint64) map[string]any {
	members := map[string]any{}
	accepted, active := 0, 0
	for i, m := range sess.Members {
		next := sess.NextIndex
		if i+1 < len(sess.Members) {
			next = sess.Members[i+1].Index
		}
		mj := map[string]any{
			"next":          next,
			"joinTime":      ts(m.JoinTime),
			"constants":     m.Constants,
			"properties":    map[string]any{"system": m.System, "custom": m.Custom},
			"gamertag":      m.Gamertag,
			"deviceToken":   deviceToken(m.XUID),
			"nat":           "moderate",
			"activeTitleId": m.ActiveTitleID,
			"reserved":      m.Reserved,
		}
		if m.Roles != nil {
			mj["roles"] = m.Roles
		}
		members[strconv.Itoa(m.Index)] = mj
		if !m.Reserved {
			accepted++
		}
		if a, _ := m.System["active"].(bool); a {
			active++
		}
	}
	first := sess.NextIndex
	if len(sess.Members) > 0 {
		first = sess.Members[0].Index
	}
	sys := sess.System
	if sys == nil {
		sys = map[string]any{}
	}
	out := map[string]any{
		"contractVersion": 107,
		"correlationId":   sess.CorrelationID,
		"branch":          sess.Branch,
		"changeNumber":    sess.ChangeNumber,
		"startTime":       ts(sess.StartTime),
		"constants":       sess.Constants,
		"properties":      map[string]any{"system": sys, "custom": sess.Custom},
		"membersInfo":     map[string]any{"first": first, "next": sess.NextIndex, "count": len(sess.Members), "accepted": accepted, "active": active},
		"members":         members,
	}
	if sess.Servers != nil {
		out["servers"] = sess.Servers
	}
	if sess.RoleTypes != nil {
		out["roleTypes"] = sess.RoleTypes
	}
	return out
}

func (s *Service) reply(w http.ResponseWriter, status int, ref Ref, out map[string]any, tag string) {
	w.Header().Set("ETag", tag)
	w.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))
	w.Header().Set("Content-Location", ref.path())
	writeJSON(w, status, out)
}

func (s *Service) get(w http.ResponseWriter, r *http.Request, c *Caller, ref Ref, byHandle bool) {
	s.mu.Lock()
	s.init()
	sess := s.sessions[ref.key()]
	if sess == nil {
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
		return
	}
	out, tag := s.render(sess, c.XUID), s.etag(sess)
	s.mu.Unlock()
	s.reply(w, http.StatusOK, sess.Ref, out, tag)
}

// tap sends a shoulder tap to every subscribed member's RTA connection.
func (s *Service) tap(sess *Session, skip uint64) {
	if s.Hub == nil {
		return
	}
	s.mu.Lock()
	var conns []string
	for _, m := range sess.Members {
		if m.Connection != "" && m.XUID != skip {
			conns = append(conns, m.Connection)
		}
	}
	data := map[string]any{"shoulderTaps": []any{map[string]any{
		"resource":     sess.Ref.SCID + "~" + sess.Ref.Template + "~" + sess.Ref.Name,
		"changeNumber": sess.ChangeNumber,
		"branch":       sess.Branch,
	}}}
	s.mu.Unlock()
	for _, id := range conns {
		if c := s.Hub.Conn(id); c != nil {
			c.Event(rta.Prefix("https://sessiondirectory.xboxlive.com/connections"), data)
		}
	}
}

// ConnectionClosed drops the members whose RTA connection went away (the
// sessions require a connection for active members) and taps the rest.
func (s *Service) ConnectionClosed(connID string) {
	s.mu.Lock()
	s.init()
	var changed []*Session
	for k, sess := range s.sessions {
		before := len(sess.Members)
		kept := sess.Members[:0]
		for _, m := range sess.Members {
			if m.Connection != connID {
				kept = append(kept, m)
			}
		}
		sess.Members = kept
		if len(kept) != before {
			sess.ChangeNumber++
			if len(kept) == 0 {
				delete(s.sessions, k)
			}
			changed = append(changed, sess)
		}
	}
	s.mu.Unlock()
	for _, sess := range changed {
		s.Log.Info("mpsd member dropped with its connection", "template", sess.Ref.Template, "name", sess.Ref.Name)
		s.tap(sess, 0)
	}
}

func (s *Service) browse(w http.ResponseWriter, r *http.Request, c *Caller, parts []string) {
	q := r.URL.Query()
	var xuids []uint64
	for _, x := range q["xuid"] {
		if v, err := strconv.ParseUint(x, 10, 64); err == nil {
			xuids = append(xuids, v)
		}
	}
	if r.Method == http.MethodPost {
		body, _ := readBody(r)
		if arr, ok := body["xuids"].([]any); ok {
			for _, x := range arr {
				if xs, ok := x.(string); ok {
					if v, err := strconv.ParseUint(xs, 10, 64); err == nil {
						xuids = append(xuids, v)
					}
				}
			}
		}
	}
	scid := strings.ToLower(parts[1])
	tmpl := ""
	if len(parts) >= 4 && strings.EqualFold(parts[2], "sessiontemplates") {
		tmpl = strings.ToLower(parts[3])
	}
	s.mu.Lock()
	s.init()
	results := []any{}
	for _, sess := range s.sessions {
		if strings.ToLower(sess.Ref.SCID) != scid || (tmpl != "" && strings.ToLower(sess.Ref.Template) != tmpl) {
			continue
		}
		for _, m := range sess.Members {
			for _, x := range xuids {
				if m.XUID == x {
					results = append(results, map[string]any{
						"sessionRef": sess.Ref, "status": "active", "visibility": "open", "joinRestriction": "none",
						"myTurn": false, "startTime": ts(sess.StartTime), "xuid": strconv.FormatUint(x, 10), "accepted": len(sess.Members),
					})
				}
			}
		}
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

func parseRef(v any) (Ref, bool) {
	m := obj(v)
	if m == nil {
		return Ref{}, false
	}
	r := Ref{}
	r.SCID, _ = m["scid"].(string)
	r.Template, _ = m["templateName"].(string)
	r.Name, _ = m["name"].(string)
	return r, r.SCID != "" && r.Template != "" && r.Name != ""
}

func (s *Service) postHandle(w http.ResponseWriter, r *http.Request, c *Caller) {
	body, err := readBody(r)
	if err != nil {
		errJSON(w, http.StatusBadRequest, "bad json")
		return
	}
	ref, ok := parseRef(body["sessionRef"])
	if !ok {
		errJSON(w, http.StatusBadRequest, "sessionRef required")
		return
	}
	typ, _ := body["type"].(string)
	h := &Handle{ID: rta.NewID(), Type: typ, Ref: ref, OwnerXUID: c.XUID, TitleID: c.Title, Created: time.Now(), Expiration: time.Now().Add(time.Hour)}
	s.mu.Lock()
	s.init()
	exists := s.sessions[ref.key()] != nil
	switch typ {
	case "activity":
		for id, x := range s.handles {
			if x.Type == "activity" && x.OwnerXUID == c.XUID && strings.EqualFold(x.Ref.SCID, ref.SCID) {
				delete(s.handles, id)
			}
		}
		h.Expiration = time.Now().Add(24 * time.Hour)
	case "invite":
		xs, _ := body["invitedXuid"].(string)
		h.Invited, _ = strconv.ParseUint(xs, 10, 64)
		if attr := obj(body["inviteAttributes"]); attr != nil {
			if t, ok := attr["titleId"].(string); ok && t != "" {
				h.TitleID = t
			}
			h.Context, _ = attr["context"].(string)
			h.ContextStr, _ = attr["contextString"].(string)
		}
		if h.Invited == 0 {
			s.mu.Unlock()
			errJSON(w, http.StatusBadRequest, "invitedXuid required")
			return
		}
	case "transfer":
		if !exists {
			s.mu.Unlock()
			errJSON(w, http.StatusForbidden, "target session does not exist")
			return
		}
		if o, ok := parseRef(body["originSessionRef"]); ok {
			h.Origin = &o
		}
	default:
		s.mu.Unlock()
		errJSON(w, http.StatusBadRequest, "unsupported handle type")
		return
	}
	s.handles[strings.ToLower(h.ID)] = h
	s.gcHandles()
	s.mu.Unlock()
	s.Log.Info("mpsd handle", "type", typ, "template", ref.Template, "by", c.XUID, "invited", h.Invited)
	if typ == "invite" {
		s.deliverInvite(r.Context(), h)
	}
	writeJSON(w, http.StatusCreated, s.handleJSON(r.Context(), h))
}

func (s *Service) gcHandles() {
	now := time.Now()
	for id, h := range s.handles {
		if now.After(h.Expiration) {
			delete(s.handles, id)
		}
	}
}

func (s *Service) handleJSON(ctx context.Context, h *Handle) map[string]any {
	out := map[string]any{
		"id": h.ID, "type": h.Type, "version": 1, "sessionRef": h.Ref,
		"ownerXuid": strconv.FormatUint(h.OwnerXUID, 10), "titleId": h.TitleID,
		"createTime": ts(h.Created), "expiration": ts(h.Expiration),
	}
	if h.Type == "invite" {
		out["invitedXuid"] = strconv.FormatUint(h.Invited, 10)
		out["senderXuid"] = strconv.FormatUint(h.OwnerXUID, 10)
		out["inviteProtocol"] = "game"
		attr := map[string]any{"titleId": h.TitleID}
		if h.Context != "" {
			attr["context"] = h.Context
		}
		if h.ContextStr != "" {
			attr["contextString"] = h.ContextStr
		}
		out["inviteAttributes"] = attr
	}
	if h.Origin != nil {
		out["originSessionRef"] = *h.Origin
	}
	return out
}

// deliverInvite pushes the game invite to the invitee's notify subscription.
func (s *Service) deliverInvite(ctx context.Context, h *Handle) {
	if s.Hub == nil {
		return
	}
	gt := ""
	if u, err := s.Dir.ByXUID(ctx, h.OwnerXUID); err == nil {
		gt = u.Gamertag
	}
	data := map[string]any{"inviteHandle": map[string]any{
		"id":             h.ID,
		"invitedXuid":    strconv.FormatUint(h.Invited, 10),
		"senderXuid":     strconv.FormatUint(h.OwnerXUID, 10),
		"inviteProtocol": "game",
		"expiration":     ts(h.Expiration),
		"sessionRef":     h.Ref,
		"inviteInfo": map[string]any{
			"sender": gt, "senderModernGamertag": gt, "senderModernGamertagSuffix": "",
			"senderUniqueModernGamertag": gt, "senderImageUrl": "",
		},
	}}
	n := s.Hub.ToXUID(h.Invited, rta.Prefix("https://notify.xboxlive.com/users/"), data)
	s.Log.Info("mpsd invite delivered", "to", h.Invited, "subscriptions", n)
}

func (s *Service) handle(w http.ResponseWriter, r *http.Request, c *Caller, id string) {
	s.mu.Lock()
	s.init()
	h := s.handles[strings.ToLower(id)]
	if h != nil && r.Method == http.MethodDelete && h.OwnerXUID == c.XUID {
		delete(s.handles, strings.ToLower(id))
	}
	s.mu.Unlock()
	if h == nil {
		errJSON(w, http.StatusNotFound, "handle not found")
		return
	}
	switch r.Method {
	case http.MethodDelete:
		w.WriteHeader(http.StatusOK)
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.handleJSON(r.Context(), h))
	default:
		errJSON(w, http.StatusMethodNotAllowed, "method")
	}
}

func (s *Service) queryHandles(w http.ResponseWriter, r *http.Request, c *Caller) {
	body, err := readBody(r)
	if err != nil {
		errJSON(w, http.StatusBadRequest, "bad json")
		return
	}
	scid, _ := body["scid"].(string)
	owners := map[uint64]bool{}
	ow := obj(body["owners"])
	if xs, ok := ow["xuids"].([]any); ok {
		for _, x := range xs {
			if v, err := strconv.ParseUint(fmt.Sprint(x), 10, 64); err == nil {
				owners[v] = true
			}
		}
	}
	if people := obj(ow["people"]); people != nil && s.Friends != nil {
		mx, _ := people["monikerXuid"].(string)
		x, _ := strconv.ParseUint(mx, 10, 64)
		acct := c.Account
		if x != 0 && x != c.XUID {
			if u, err := s.Dir.ByXUID(r.Context(), x); err == nil {
				acct = u.AccountID
			}
		}
		fs, err := s.Friends(r.Context(), acct)
		if err == nil {
			for _, f := range fs {
				owners[ident.XUIDFor(f)] = true
			}
		}
	}
	s.mu.Lock()
	s.init()
	type item struct {
		h    *Handle
		sess *Session
	}
	var items []item
	for _, h := range s.handles {
		if h.Type != "activity" || !owners[h.OwnerXUID] || (scid != "" && !strings.EqualFold(h.Ref.SCID, scid)) {
			continue
		}
		items = append(items, item{h, s.sessions[h.Ref.key()]})
	}
	results := []any{}
	sort.Slice(items, func(i, j int) bool { return items[i].h.Created.Before(items[j].h.Created) })
	for _, it := range items {
		if it.sess == nil {
			continue
		}
		jr, _ := it.sess.System["joinRestriction"].(string)
		if jr == "" {
			jr = "none"
		}
		closed, _ := it.sess.System["closed"].(bool)
		results = append(results, map[string]any{
			"type": "activity", "id": it.h.ID, "sessionRef": it.h.Ref,
			"ownerXuid": strconv.FormatUint(it.h.OwnerXUID, 10), "titleId": it.h.TitleID,
			"customProperties": map[string]any{},
			"relatedInfo": map[string]any{
				"membersCount": len(it.sess.Members), "maxMembersCount": s.maxMembers(it.sess),
				"joinRestriction": jr, "visibility": "open", "closed": closed,
			},
		})
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}
