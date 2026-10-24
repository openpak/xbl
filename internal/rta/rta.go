// Package rta is the Real-Time Activity websocket (wss://rta.xboxlive.com/connect,
// subprotocol rta.xboxlive.com.V2). Clients subscribe to resource URIs and
// the services push events on them:
//
//	client: [1, seq, "<uri>"]         subscribe
//	client: [2, seq, subId]           unsubscribe
//	server: [1, seq, code, subId, data]  subscribe result (always 5 elements)
//	server: [2, seq, code]            unsubscribe result
//	server: [3, subId, data]          event
//	server: [4]                       resync
package rta

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/openpak/xbl/internal/ws"
)

// Caller is the authenticated user of a socket.
type Caller struct {
	Account string
	XUID    uint64
}

// Authenticator reads the caller from the upgrade request.
type Authenticator func(r *http.Request) (*Caller, error)

// Resource decides what a subscription to uri returns. ok=false falls through
// to the next resource; the default answers success with null data.
type Resource func(c *Conn, uri string) (data any, ok bool)

// Hub holds every live socket.
type Hub struct {
	Auth      Authenticator
	Log       *slog.Logger
	Resources []Resource
	// OnClose runs after a socket closes (MPSD drops its connection id).
	OnClose func(c *Conn)

	mu    sync.Mutex
	conns map[string]*Conn
}

// Conn is one client socket.
type Conn struct {
	ID     string // the MPSD ConnectionId
	Caller Caller

	ws      *ws.Conn
	mu      sync.Mutex
	subs    map[int]string // subId -> uri
	nextSub int
}

// NewID is a random GUID string.
func NewID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c, err := h.Auth(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	sock, err := ws.Accept(w, r, "rta.xboxlive.com.V2")
	if err != nil {
		return
	}
	conn := &Conn{ID: NewID(), Caller: *c, ws: sock, subs: map[int]string{}, nextSub: 1}
	h.mu.Lock()
	if h.conns == nil {
		h.conns = map[string]*Conn{}
	}
	h.conns[conn.ID] = conn
	h.mu.Unlock()
	h.Log.Info("rta connected", "conn", conn.ID, "xuid", c.XUID)
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				if sock.Ping() != nil {
					return
				}
			}
		}
	}()
	defer func() {
		close(stop)
		sock.Close()
		h.mu.Lock()
		delete(h.conns, conn.ID)
		h.mu.Unlock()
		h.Log.Info("rta disconnected", "conn", conn.ID, "xuid", c.XUID)
		if h.OnClose != nil {
			h.OnClose(conn)
		}
	}()
	for {
		_, msg, err := sock.Read()
		if err != nil {
			return
		}
		h.handle(conn, msg)
	}
}

func (h *Hub) handle(c *Conn, msg []byte) {
	var a []json.RawMessage
	if json.Unmarshal(msg, &a) != nil || len(a) < 2 {
		return
	}
	var typ, seq int
	if json.Unmarshal(a[0], &typ) != nil || json.Unmarshal(a[1], &seq) != nil {
		return
	}
	switch typ {
	case 1:
		var uri string
		if len(a) < 3 || json.Unmarshal(a[2], &uri) != nil {
			return
		}
		var data any
		for _, res := range h.Resources {
			if d, ok := res(c, uri); ok {
				data = d
				break
			}
		}
		c.mu.Lock()
		id := c.nextSub
		c.nextSub++
		c.subs[id] = uri
		c.mu.Unlock()
		h.Log.Info("rta subscribe", "conn", c.ID, "sub", id, "uri", uri)
		c.send([]any{1, seq, 0, id, data})
	case 2:
		var id int
		if len(a) >= 3 {
			json.Unmarshal(a[2], &id)
		}
		c.mu.Lock()
		delete(c.subs, id)
		c.mu.Unlock()
		c.send([]any{2, seq, 0})
	}
}

func (c *Conn) send(v any) {
	b, _ := json.Marshal(v)
	c.ws.WriteText(b)
}

// Event sends data on every subscription of c whose URI matches.
func (c *Conn) Event(match func(uri string) bool, data any) int {
	c.mu.Lock()
	var ids []int
	for id, uri := range c.subs {
		if match(uri) {
			ids = append(ids, id)
		}
	}
	c.mu.Unlock()
	for _, id := range ids {
		c.send([]any{3, id, data})
	}
	return len(ids)
}

// Conn returns a live socket by id.
func (h *Hub) Conn(id string) *Conn {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.conns[id]
}

// ToXUID sends data on every matching subscription of every socket of xuid.
func (h *Hub) ToXUID(xuid uint64, match func(uri string) bool, data any) int {
	h.mu.Lock()
	var cs []*Conn
	for _, c := range h.conns {
		if c.Caller.XUID == xuid {
			cs = append(cs, c)
		}
	}
	h.mu.Unlock()
	n := 0
	for _, c := range cs {
		n += c.Event(match, data)
	}
	return n
}

// Online reports whether xuid has a live socket.
func (h *Hub) Online(xuid uint64) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, c := range h.conns {
		if c.Caller.XUID == xuid {
			return true
		}
	}
	return false
}

// Prefix matches URIs that start with p, case-insensitively.
func Prefix(p string) func(string) bool {
	p = strings.ToLower(p)
	return func(u string) bool { return strings.HasPrefix(strings.ToLower(u), p) }
}

// Broadcast sends data on every matching subscription of every socket.
func (h *Hub) Broadcast(match func(uri string) bool, data any) int {
	h.mu.Lock()
	cs := make([]*Conn, 0, len(h.conns))
	for _, c := range h.conns {
		cs = append(cs, c)
	}
	h.mu.Unlock()
	n := 0
	for _, c := range cs {
		n += c.Event(match, data)
	}
	return n
}
