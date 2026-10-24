package svc

import (
	"bytes"
	"context"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openpak/xbl/internal/core"
	"github.com/openpak/xbl/internal/ident"
	"github.com/openpak/xbl/internal/rta"
)

// Caller is the authenticated user.
type Caller struct {
	Account string
	XUID    uint64
	Title   string
}

// Core is the account-core surface the people services read.
type Core interface {
	ListFriends(ctx context.Context, account string) ([]core.Friend, error)
	GetPresence(ctx context.Context, accounts []string) (map[string]core.Presence, error)
	GetAvatar(ctx context.Context, accountID string, size uint32) ([]byte, error)
}

// Directory resolves identities.
type Directory interface {
	ByAccount(ctx context.Context, account string) (*ident.User, error)
	ByXUID(ctx context.Context, xuid uint64) (*ident.User, error)
	ByGamertag(ctx context.Context, tag string) (*ident.User, error)
}

// People serves profile, social, peoplehub, presence, privacy and the
// smaller per-user services. Friends are the account core's; presence is
// what titles report here, else the core's network-wide presence.
type People struct {
	Auth      func(r *http.Request) (*Caller, error)
	Dir       Directory
	Core      Core
	Hub       *rta.Hub
	Log       *slog.Logger
	TitleName map[string]string // title id -> display name
	ImageHost string            // e.g. https://images-eds.xboxlive.com

	mu       sync.Mutex
	presence map[uint64]*presenceRec
}

type presenceRec struct {
	Title string
	State string
	Rich  string
	At    time.Time
}

// heartbeat is how often a title re-posts presence; a record older than
// twice this is stale.
const heartbeat = 300

func (p *People) write(w http.ResponseWriter, status int, v any) { WriteJSON(w, status, v) }

var userRe = regexp.MustCompile(`(?i)^/users/(me|xuid\((\d+)\)|gt\(([^)]*)\))(/.*)?$`)

// target resolves the user a /users/... path names.
func (p *People) target(ctx context.Context, c *Caller, path string) (*ident.User, string, bool) {
	m := userRe.FindStringSubmatch(path)
	if m == nil {
		return nil, "", false
	}
	rest := strings.ToLower(m[4])
	switch {
	case strings.EqualFold(m[1], "me"):
		u, err := p.Dir.ByAccount(ctx, c.Account)
		return u, rest, err == nil
	case m[2] != "":
		x, _ := strconv.ParseUint(m[2], 10, 64)
		if x == c.XUID {
			u, err := p.Dir.ByAccount(ctx, c.Account)
			return u, rest, err == nil
		}
		u, err := p.Dir.ByXUID(ctx, x)
		return u, rest, err == nil
	default:
		u, err := p.Dir.ByGamertag(ctx, m[3])
		return u, rest, err == nil
	}
}

func (p *People) friends(ctx context.Context, account string) []*ident.User {
	fs, err := p.Core.ListFriends(ctx, account)
	if err != nil {
		p.Log.Warn("people: friends unavailable", "err", err)
		return nil
	}
	out := make([]*ident.User, 0, len(fs))
	for _, f := range fs {
		if u, err := p.Dir.ByAccount(ctx, f.AccountID); err == nil {
			out = append(out, u)
		}
	}
	return out
}

func (p *People) picURL(u *ident.User) string {
	h := p.ImageHost
	if h == "" {
		h = "https://images-eds.xboxlive.com"
	}
	return h + "/image?xuid=" + u.XUIDString() + "&format=png"
}

// ---- profile.xboxlive.com ----

func (p *People) setting(u *ident.User, id string) (string, bool) {
	switch id {
	case "Gamertag", "ModernGamertag", "UniqueModernGamertag", "GameDisplayName", "AppDisplayName":
		return u.Gamertag, true
	case "ModernGamertagSuffix", "RealName", "Watermarks", "PreferredColor":
		return "", true
	case "Gamerscore", "TenureLevel":
		return "0", true
	case "GameDisplayPicRaw", "AppDisplayPicRaw", "PublicGamerpic":
		return p.picURL(u), true
	case "AccountTier":
		return "Gold", true
	case "XboxOneRep":
		return "GoodPlayer", true
	case "Bio":
		return u.Bio, true
	case "Location":
		return u.Country, true
	}
	return "", false
}

func (p *People) profileUser(u *ident.User, settings []string) map[string]any {
	ss := []any{}
	for _, id := range settings {
		if v, ok := p.setting(u, id); ok {
			ss = append(ss, map[string]any{"id": id, "value": v})
		}
	}
	return map[string]any{"id": u.XUIDString(), "hostId": u.XUIDString(), "settings": ss, "isSponsoredUser": false}
}

// Profile serves profile.xboxlive.com.
func (p *People) Profile(w http.ResponseWriter, r *http.Request) {
	c, err := p.Auth(r)
	if err != nil {
		p.write(w, http.StatusUnauthorized, nil)
		return
	}
	ctx := r.Context()
	path := r.URL.Path
	if strings.EqualFold(path, "/users/batch/profile/settings") && r.Method == http.MethodPost {
		var req struct {
			UserIds  []string `json:"userIds"`
			Settings []string `json:"settings"`
		}
		json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req)
		users := []any{}
		for _, id := range req.UserIds {
			x, err := strconv.ParseUint(id, 10, 64)
			if err != nil {
				continue
			}
			var u *ident.User
			if x == c.XUID {
				u, err = p.Dir.ByAccount(ctx, c.Account)
			} else {
				u, err = p.Dir.ByXUID(ctx, x)
			}
			if err == nil {
				users = append(users, p.profileUser(u, req.Settings))
			}
		}
		p.write(w, http.StatusOK, map[string]any{"profileUsers": users})
		return
	}
	settings := strings.Split(r.URL.Query().Get("settings"), ",")
	u, rest, ok := p.target(ctx, c, path)
	if !ok {
		p.write(w, http.StatusNotFound, map[string]any{"code": 404})
		return
	}
	switch {
	case rest == "/profile/settings":
		p.write(w, http.StatusOK, map[string]any{"profileUsers": []any{p.profileUser(u, settings)}})
	case strings.HasPrefix(rest, "/profile/settings/people/"):
		users := []any{}
		for _, f := range p.friends(ctx, u.AccountID) {
			users = append(users, p.profileUser(f, settings))
		}
		p.write(w, http.StatusOK, map[string]any{"profileUsers": users})
	default:
		p.write(w, http.StatusNotFound, map[string]any{"code": 404})
	}
}

// Image serves gamerpics: the account's avatar, else a plain tile.
func (p *People) Image(w http.ResponseWriter, r *http.Request) {
	var pic []byte
	if x, err := strconv.ParseUint(r.URL.Query().Get("xuid"), 10, 64); err == nil {
		if u, err := p.Dir.ByXUID(r.Context(), x); err == nil && p.Core != nil {
			pic, _ = p.Core.GetAvatar(r.Context(), u.AccountID, 256)
		}
	}
	if len(pic) == 0 {
		pic = defaultPic()
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Write(pic)
}

var (
	picOnce sync.Once
	picPNG  []byte
)

func defaultPic() []byte {
	picOnce.Do(func() {
		img := image.NewRGBA(image.Rect(0, 0, 64, 64))
		for y := 0; y < 64; y++ {
			for x := 0; x < 64; x++ {
				img.Set(x, y, color.RGBA{0x1f, 0x8a, 0xc0, 0xff})
			}
		}
		var b bytes.Buffer
		png.Encode(&b, img)
		picPNG = b.Bytes()
	})
	return picPNG
}

// ---- presence ----

func (p *People) record(x uint64) *presenceRec {
	p.mu.Lock()
	defer p.mu.Unlock()
	r := p.presence[x]
	if r == nil || time.Since(r.At) > 2*heartbeat*time.Second {
		return nil
	}
	cp := *r
	return &cp
}

func (p *People) titleName(id string) string {
	if n, ok := p.TitleName[id]; ok {
		return n
	}
	return ""
}

// presenceJSON is one presence record.
func (p *People) presenceJSON(ctx context.Context, u *ident.User, coreOnline bool) map[string]any {
	rec := p.record(u.XUID)
	if rec == nil && p.Hub != nil && p.Hub.Online(u.XUID) {
		rec = &presenceRec{State: "active", At: time.Now()}
	}
	if rec == nil {
		if coreOnline {
			return map[string]any{"xuid": u.XUIDString(), "state": "Online", "devices": []any{}}
		}
		return map[string]any{"xuid": u.XUIDString(), "state": "Offline"}
	}
	titles := []any{}
	if rec.Title != "" {
		t := map[string]any{"id": rec.Title, "name": p.titleName(rec.Title), "lastModified": ts(rec.At),
			"state": "active", "placement": "full"}
		if rec.Rich != "" {
			t["activity"] = map[string]any{"richPresence": rec.Rich}
		}
		titles = append(titles, t)
	}
	return map[string]any{"xuid": u.XUIDString(), "state": "Online",
		"devices": []any{map[string]any{"type": "Nintendo", "titles": titles}}}
}

func ts(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.0000000Z") }

func (p *People) coreOnline(ctx context.Context, us []*ident.User) map[string]bool {
	ids := make([]string, 0, len(us))
	for _, u := range us {
		ids = append(ids, u.AccountID)
	}
	out := map[string]bool{}
	if len(ids) == 0 || p.Core == nil {
		return out
	}
	pr, err := p.Core.GetPresence(ctx, ids)
	if err != nil {
		return out
	}
	for a := range pr {
		out[a] = true
	}
	return out
}

// Presence serves userpresence.xboxlive.com.
func (p *People) Presence(w http.ResponseWriter, r *http.Request) {
	c, err := p.Auth(r)
	if err != nil {
		p.write(w, http.StatusUnauthorized, nil)
		return
	}
	ctx := r.Context()
	if strings.EqualFold(r.URL.Path, "/users/batch") && r.Method == http.MethodPost {
		var req struct {
			Users []string `json:"users"`
			Group string   `json:"group"`
		}
		json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req)
		var us []*ident.User
		if req.Group != "" {
			us = p.friends(ctx, c.Account)
		}
		for _, id := range req.Users {
			if x, err := strconv.ParseUint(id, 10, 64); err == nil {
				if u, err := p.Dir.ByXUID(ctx, x); err == nil {
					us = append(us, u)
				}
			}
		}
		on := p.coreOnline(ctx, us)
		out := []any{}
		for _, u := range us {
			out = append(out, p.presenceJSON(ctx, u, on[u.AccountID]))
		}
		p.write(w, http.StatusOK, out)
		return
	}
	u, rest, ok := p.target(ctx, c, r.URL.Path)
	if !ok {
		p.write(w, http.StatusNotFound, map[string]any{"code": 404})
		return
	}
	switch {
	case strings.HasPrefix(rest, "/devices/current/titles/current") && u.XUID == c.XUID:
		switch r.Method {
		case http.MethodPost:
			var req struct {
				State    string `json:"state"`
				Activity struct {
					RichPresence struct {
						ID string `json:"id"`
					} `json:"richPresence"`
				} `json:"activity"`
			}
			json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req)
			p.setPresence(u.XUID, c.Title, req.State, req.Activity.RichPresence.ID)
			w.Header().Set("X-Heartbeat-After", strconv.Itoa(heartbeat))
			w.WriteHeader(http.StatusOK)
		case http.MethodDelete:
			p.mu.Lock()
			delete(p.presence, u.XUID)
			p.mu.Unlock()
			p.publishPresence(u.XUID, c.Title, false)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	case rest == "" || rest == "/":
		on := p.coreOnline(ctx, []*ident.User{u})
		p.write(w, http.StatusOK, p.presenceJSON(ctx, u, on[u.AccountID]))
	default:
		p.write(w, http.StatusNotFound, map[string]any{"code": 404})
	}
}

func (p *People) setPresence(x uint64, title, state, rich string) {
	p.mu.Lock()
	if p.presence == nil {
		p.presence = map[uint64]*presenceRec{}
	}
	old := p.presence[x]
	fresh := old == nil || time.Since(old.At) > 2*heartbeat*time.Second
	if state == "" {
		state = "active"
	}
	p.presence[x] = &presenceRec{Title: title, State: state, Rich: rich, At: time.Now()}
	p.mu.Unlock()
	if fresh {
		p.publishPresence(x, title, true)
	}
}

// PresenceResource answers presence subscriptions with the current record.
func (p *People) PresenceResource(c *rta.Conn, uri string) (any, bool) {
	low := strings.ToLower(uri)
	if !strings.HasPrefix(low, "https://userpresence.xboxlive.com/users/xuid(") {
		return nil, false
	}
	m := regexp.MustCompile(`xuid\((\d+)\)`).FindStringSubmatch(low)
	if m == nil {
		return nil, true
	}
	x, _ := strconv.ParseUint(m[1], 10, 64)
	u, err := p.Dir.ByXUID(context.Background(), x)
	if err != nil {
		return nil, true
	}
	on := p.coreOnline(context.Background(), []*ident.User{u})
	return p.presenceJSON(context.Background(), u, on[u.AccountID]), true
}

func (p *People) publishPresence(x uint64, title string, online bool) {
	if p.Hub == nil {
		return
	}
	xs := strconv.FormatUint(x, 10)
	state := "Nintendo:false"
	ts := "Ended"
	if online {
		state, ts = "Nintendo:true", "Started"
	}
	p.Hub.Broadcast(rta.Prefix("https://userpresence.xboxlive.com/users/xuid("+xs+")/devices"), state)
	if title != "" {
		p.Hub.Broadcast(rta.Prefix("https://userpresence.xboxlive.com/users/xuid("+xs+")/titles/"+title), ts)
	}
}

// ---- social.xboxlive.com and peoplehub.xboxlive.com ----

// Social serves social.xboxlive.com/users/{who}/people.
func (p *People) Social(w http.ResponseWriter, r *http.Request) {
	c, err := p.Auth(r)
	if err != nil {
		p.write(w, http.StatusUnauthorized, nil)
		return
	}
	u, rest, ok := p.target(r.Context(), c, r.URL.Path)
	if !ok || !strings.HasPrefix(rest, "/people") {
		p.write(w, http.StatusNotFound, map[string]any{"code": 404})
		return
	}
	people := []any{}
	if !strings.EqualFold(r.URL.Query().Get("view"), "Favorite") {
		for _, f := range p.friends(r.Context(), u.AccountID) {
			people = append(people, map[string]any{"xuid": f.XUIDString(), "isFavorite": false, "isFollowingCaller": true, "socialNetworks": []any{}})
		}
	}
	p.write(w, http.StatusOK, map[string]any{"totalCount": len(people), "people": people})
}

// PeopleHub serves peoplehub.xboxlive.com (the Social Manager's graph).
func (p *People) PeopleHub(w http.ResponseWriter, r *http.Request) {
	c, err := p.Auth(r)
	if err != nil {
		p.write(w, http.StatusUnauthorized, nil)
		return
	}
	ctx := r.Context()
	u, rest, ok := p.target(ctx, c, r.URL.Path)
	if !ok {
		p.write(w, http.StatusNotFound, map[string]any{"code": 404})
		return
	}
	var us []*ident.User
	switch {
	case strings.HasPrefix(rest, "/people/social"):
		us = p.friends(ctx, u.AccountID)
	case strings.HasPrefix(rest, "/people/batch"):
		var req struct {
			Xuids []string `json:"xuids"`
		}
		json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req)
		for _, id := range req.Xuids {
			if x, err := strconv.ParseUint(id, 10, 64); err == nil {
				if v, err := p.Dir.ByXUID(ctx, x); err == nil {
					us = append(us, v)
				}
			}
		}
	default:
		p.write(w, http.StatusNotFound, map[string]any{"code": 404})
		return
	}
	on := p.coreOnline(ctx, us)
	people := []any{}
	for _, f := range us {
		pr := p.presenceJSON(ctx, f, on[f.AccountID])
		state, _ := pr["state"].(string)
		details := []any{}
		if rec := p.record(f.XUID); rec != nil && rec.Title != "" {
			details = append(details, map[string]any{"Device": "Nintendo", "PresenceText": p.titleName(rec.Title), "State": "active", "TitleId": rec.Title, "IsPrimary": true})
		} else if state == "Online" {
			details = append(details, map[string]any{"Device": "Nintendo", "PresenceText": "Online", "State": "active", "TitleId": "", "IsPrimary": true})
		}
		text := "Offline"
		if state == "Online" {
			text = "Online"
		}
		people = append(people, map[string]any{
			"xuid": f.XUIDString(), "isFavorite": false, "isFollowingCaller": true, "isFollowedByCaller": true,
			"isIdentityShared": false, "displayName": f.Gamertag, "realName": "", "displayPicRaw": p.picURL(f),
			"showUserAsAvatar": "0", "gamertag": f.Gamertag, "modernGamertag": f.Gamertag, "modernGamertagSuffix": "",
			"uniqueModernGamertag": f.Gamertag, "gamerScore": "0", "xboxOneRep": "GoodPlayer", "useAvatar": false,
			"presenceState": state, "presenceText": text, "presenceDetails": details,
			"titleHistory":   map[string]any{"LastTimePlayed": nil},
			"preferredColor": map[string]any{"primaryColor": "107c10", "secondaryColor": "102b14", "tertiaryColor": "155715"},
		})
	}
	p.write(w, http.StatusOK, map[string]any{"people": people})
}

// ---- privacy, notify, stats and the rest ----

// Privacy allows everything the account core allows; blocks already hide
// people from the friend list.
func (p *People) Privacy(w http.ResponseWriter, r *http.Request) {
	if _, err := p.Auth(r); err != nil {
		p.write(w, http.StatusUnauthorized, nil)
		return
	}
	low := strings.ToLower(r.URL.Path)
	switch {
	case strings.HasSuffix(low, "/people/avoid"), strings.HasSuffix(low, "/people/mute"):
		p.write(w, http.StatusOK, map[string]any{"users": []any{}})
	case strings.HasSuffix(low, "/permission/validate") && r.Method == http.MethodGet:
		p.write(w, http.StatusOK, map[string]any{"isAllowed": true, "reasons": []any{}})
	case strings.HasSuffix(low, "/permission/validate"):
		var req struct {
			Users       []map[string]any `json:"users"`
			Permissions []string         `json:"permissions"`
		}
		json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req)
		resps := []any{}
		for _, u := range req.Users {
			perms := []any{}
			for _, pm := range req.Permissions {
				perms = append(perms, map[string]any{"permission": pm, "isAllowed": true, "reasons": []any{}})
			}
			resps = append(resps, map[string]any{"user": u, "permissions": perms})
		}
		p.write(w, http.StatusOK, map[string]any{"responses": resps})
	default:
		p.write(w, http.StatusNotFound, map[string]any{"code": 404})
	}
}

// Notify serves notify.xboxlive.com endpoint registration.
func (p *People) Notify(w http.ResponseWriter, r *http.Request) {
	if _, err := p.Auth(r); err != nil {
		p.write(w, http.StatusUnauthorized, nil)
		return
	}
	low := strings.ToLower(r.URL.Path)
	switch {
	case low == "/system/notifications/endpoints" && r.Method == http.MethodPost:
		io.Copy(io.Discard, io.LimitReader(r.Body, 64<<10))
		p.write(w, http.StatusOK, map[string]any{"endpointId": rta.NewID()})
	case strings.HasPrefix(low, "/system/notifications/endpoints/"):
		w.WriteHeader(http.StatusOK)
	default:
		p.write(w, http.StatusNotFound, map[string]any{"code": 404})
	}
}

// Empty answers the services a title may touch but nothing depends on:
// stats, achievements, title storage, string verification, multiplayer
// activity and leaderboards.
func (p *People) Empty(w http.ResponseWriter, r *http.Request) {
	if _, err := p.Auth(r); err != nil {
		p.write(w, http.StatusUnauthorized, nil)
		return
	}
	low := strings.ToLower(r.URL.Path)
	switch {
	case strings.HasSuffix(low, "/system/strings/validate"):
		var req struct {
			StringsToVerify []string `json:"stringstoVerify"`
		}
		json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req)
		res := []any{}
		for range req.StringsToVerify {
			res = append(res, map[string]any{"resultCode": "Success"})
		}
		p.write(w, http.StatusOK, map[string]any{"verifyStringResult": res})
	case strings.Contains(low, "/activities/query"):
		p.write(w, http.StatusOK, map[string]any{"userActivities": []any{}})
	case strings.Contains(low, "/achievements"):
		p.write(w, http.StatusOK, map[string]any{"achievements": []any{}, "pagingInfo": map[string]any{"continuationToken": nil, "totalRecords": 0}})
	case strings.Contains(low, "/stats") || strings.HasPrefix(low, "/batch"):
		p.write(w, http.StatusOK, map[string]any{"users": []any{}, "groups": []any{}})
	case r.Method == http.MethodPut || r.Method == http.MethodPost || r.Method == http.MethodDelete:
		io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
		w.WriteHeader(http.StatusOK)
	default:
		p.write(w, http.StatusNotFound, map[string]any{"code": 404})
	}
}
