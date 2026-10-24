package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// wsClient is a minimal masked-frame websocket client for tests.
type wsClient struct {
	c  net.Conn
	br *bufio.Reader
}

func (e *testEnv) dialRTA(authz string) *wsClient {
	t := e.t
	addr := strings.TrimPrefix(e.srv.URL, "http://")
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 16)
	rand.Read(key)
	fmt.Fprintf(c, "GET /connect HTTP/1.1\r\nHost: rta.xboxlive.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: rta.xboxlive.com.V2\r\nAuthorization: %s\r\n\r\n",
		base64.StdEncoding.EncodeToString(key), authz)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 101 || resp.Header.Get("Sec-WebSocket-Protocol") != "rta.xboxlive.com.V2" {
		t.Fatalf("upgrade: %v %v", resp, err)
	}
	return &wsClient{c: c, br: br}
}

func (w *wsClient) send(v any) {
	b, _ := json.Marshal(v)
	h := []byte{0x81}
	if len(b) < 126 {
		h = append(h, 0x80|byte(len(b)))
	} else {
		h = append(h, 0x80|126, byte(len(b)>>8), byte(len(b)))
	}
	mask := []byte{1, 2, 3, 4}
	h = append(h, mask...)
	for i := range b {
		b[i] ^= mask[i%4]
	}
	w.c.Write(append(h, b...))
}

func (w *wsClient) recv(t *testing.T) []any {
	t.Helper()
	w.c.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		var h [2]byte
		if _, err := io.ReadFull(w.br, h[:]); err != nil {
			t.Fatalf("ws read: %v", err)
		}
		n := int(h[1] & 0x7f)
		if n == 126 {
			var b [2]byte
			io.ReadFull(w.br, b[:])
			n = int(binary.BigEndian.Uint16(b[:]))
		}
		p := make([]byte, n)
		io.ReadFull(w.br, p)
		if h[0]&0x0f == 9 { // ping
			continue
		}
		var a []any
		if err := json.Unmarshal(p, &a); err != nil {
			t.Fatalf("ws json: %s", p)
		}
		return a
	}
}

const scid = "00000000-0000-0000-0000-000067acc3cd"

func TestLobbyInviteJoin(t *testing.T) {
	e := newEnv(t)
	alice, _ := e.signIn("alice")
	bob, _ := e.signIn("bob")
	hdr := func(a string) map[string]string {
		return map[string]string{"Authorization": a, "x-xbl-contract-version": "107"}
	}

	// Both connect RTA: MPSD connection id, and bob's invite subscription.
	ra := e.dialRTA(alice)
	ra.send([]any{1, 1, "https://sessiondirectory.xboxlive.com/connections/"})
	sub := ra.recv(t)
	if len(sub) != 5 || sub[2].(float64) != 0 {
		t.Fatalf("subscribe reply %v", sub)
	}
	connA := sub[4].(map[string]any)["ConnectionId"].(string)
	rb := e.dialRTA(bob)
	rb.send([]any{1, 1, "https://sessiondirectory.xboxlive.com/connections/"})
	connB := rb.recv(t)[4].(map[string]any)["ConnectionId"].(string)
	rb.send([]any{1, 2, "https://notify.xboxlive.com/users/xuid(123)/deviceId/current/titleId/1739375565"})
	if r := rb.recv(t); r[3].(float64) == 1 {
		t.Fatalf("subscription ids must differ: %v", r)
	}

	// Alice creates the lobby.
	path := "/serviceconfigs/" + scid + "/sessionTemplates/LobbySession/sessions/abc-123"
	me := func(conn string) map[string]any {
		return map[string]any{"constants": map[string]any{"system": map[string]any{"initialize": true}},
			"properties": map[string]any{"system": map[string]any{"active": true, "connection": conn,
				"subscription": map[string]any{"id": "sub", "changeTypes": []any{"everything"}}}}}
	}
	st, sess := e.jsonDo("PUT", "sessiondirectory.xboxlive.com", path, map[string]any{
		"properties": map[string]any{"system": map[string]any{"joinRestriction": "followed"}, "custom": map[string]any{"Joinability": "joinable_by_friends"}},
		"members":    map[string]any{"me": me(connA)},
	}, hdr(alice))
	if st != 201 {
		t.Fatalf("create: %d %v", st, sess)
	}
	mi := sess["membersInfo"].(map[string]any)
	if mi["first"].(float64) != 0 || mi["next"].(float64) != 1 || sess["members"].(map[string]any)["0"] == nil {
		t.Fatalf("members %v", sess)
	}
	if tap := ra.recv(t); tap[0].(float64) != 3 {
		t.Fatalf("expected tap, got %v", tap)
	}

	// Activity, then the friend query sees it.
	st, _ = e.jsonDo("POST", "sessiondirectory.xboxlive.com", "/handles", map[string]any{
		"type": "activity", "version": 1, "sessionRef": map[string]any{"scid": scid, "templateName": "LobbySession", "name": "abc-123"}}, hdr(alice))
	if st != 201 {
		t.Fatalf("activity: %d", st)
	}
	st, q := e.jsonDo("POST", "sessiondirectory.xboxlive.com", "/handles/query?include=relatedInfo,customProperties", map[string]any{
		"type": "activity", "scid": scid, "owners": map[string]any{"people": map[string]any{"moniker": "people", "monikerXuid": ""}}}, hdr(bob))
	if st != 200 || len(q["results"].([]any)) != 1 {
		t.Fatalf("activity query: %d %v", st, q)
	}

	// Invite bob; the invite reaches his notify subscription.
	bobXUID := sess["members"].(map[string]any)["0"].(map[string]any)["constants"].(map[string]any)["system"].(map[string]any)["xuid"].(string)
	_ = bobXUID
	_, bs := e.jsonDo("GET", "profile.xboxlive.com", "/users/me/profile/settings?settings=Gamertag", nil, hdr(bob))
	bx := bs["profileUsers"].([]any)[0].(map[string]any)["id"].(string)
	st, inv := e.jsonDo("POST", "sessiondirectory.xboxlive.com", "/handles", map[string]any{
		"type": "invite", "version": 1, "invitedXuid": bx,
		"sessionRef":       map[string]any{"scid": scid, "templateName": "LobbySession", "name": "abc-123"},
		"inviteAttributes": map[string]any{"titleId": "1739375565"}}, hdr(alice))
	if st != 201 || inv["id"] == nil {
		t.Fatalf("invite: %d %v", st, inv)
	}
	ev := rb.recv(t)
	ih := ev[2].(map[string]any)["inviteHandle"].(map[string]any)
	if ih["id"] != inv["id"] || ih["inviteInfo"].(map[string]any)["sender"] != "alice" {
		t.Fatalf("invite event %v", ev)
	}

	// Bob joins through the handle.
	req, _ := json.Marshal(map[string]any{"members": map[string]any{"me": me(connB)}})
	st, b := e.do("PUT", "sessiondirectory.xboxlive.com", "/handles/"+ih["id"].(string)+"/session", "application/json", req, hdr(bob))
	if st != 200 {
		t.Fatalf("join by handle: %d %s", st, b)
	}
	var joined map[string]any
	json.Unmarshal(b, &joined)
	if joined["membersInfo"].(map[string]any)["count"].(float64) != 2 {
		t.Fatalf("joined %v", joined)
	}
	if tap := ra.recv(t); tap[0].(float64) != 3 {
		t.Fatalf("alice expected a tap for bob's join, got %v", tap)
	}

	// Bob's socket drops: he leaves the lobby and alice is tapped.
	rb.c.Close()
	if tap := ra.recv(t); tap[0].(float64) != 3 {
		t.Fatalf("alice expected a tap for bob leaving, got %v", tap)
	}
	st, g := e.jsonDo("GET", "sessiondirectory.xboxlive.com", path, nil, hdr(alice))
	if st != 200 || g["membersInfo"].(map[string]any)["count"].(float64) != 1 {
		t.Fatalf("after drop: %d %v", st, g)
	}
	// Alice leaves: the session ends (204).
	lv, _ := json.Marshal(map[string]any{"members": map[string]any{"me": nil}})
	st, _ = e.do("PUT", "sessiondirectory.xboxlive.com", path, "application/json", lv, map[string]string{"Authorization": alice, "If-Match": "*"})
	if st != 204 {
		t.Fatalf("leave: %d", st)
	}
	st, _ = e.do("GET", "sessiondirectory.xboxlive.com", path, "", nil, hdr(alice))
	if st != 204 {
		t.Fatalf("gone: %d", st)
	}
}

func TestPeopleAndPresence(t *testing.T) {
	e := newEnv(t)
	alice, _ := e.signIn("alice")
	bob, _ := e.signIn("bob")
	h := map[string]string{"Authorization": alice}
	st, ph := e.jsonDo("GET", "peoplehub.xboxlive.com", "/users/me/people/social/decoration/presenceDetail", nil, h)
	if st != 200 || len(ph["people"].([]any)) != 1 {
		t.Fatalf("peoplehub: %d %v", st, ph)
	}
	f := ph["people"].([]any)[0].(map[string]any)
	if f["gamertag"] != "bob" || f["presenceState"] != "Offline" {
		t.Fatalf("friend %v", f)
	}
	// Bob comes online in the title.
	st, _ = e.jsonDo("POST", "userpresence.xboxlive.com", "/users/me/devices/current/titles/current", map[string]any{"state": "active"}, map[string]string{"Authorization": bob})
	if st != 200 {
		t.Fatalf("set presence %d", st)
	}
	_, ph = e.jsonDo("GET", "peoplehub.xboxlive.com", "/users/me/people/social/decoration/presenceDetail", nil, h)
	f = ph["people"].([]any)[0].(map[string]any)
	if f["presenceState"] != "Online" {
		t.Fatalf("friend after presence %v", f)
	}
	st, sp := e.jsonDo("GET", "social.xboxlive.com", "/users/me/people", nil, h)
	if st != 200 || sp["totalCount"].(float64) != 1 {
		t.Fatalf("social %d %v", st, sp)
	}
	var arr []any
	st, b := e.do("POST", "userpresence.xboxlive.com", "/users/batch", "application/json", []byte(`{"users":["`+f["xuid"].(string)+`"],"level":"all"}`), h)
	json.Unmarshal(b, &arr)
	if st != 200 || len(arr) != 1 {
		t.Fatalf("batch presence %d %s", st, b)
	}
}
