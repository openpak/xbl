// Package ws is a small RFC 6455 websocket server side: the upgrade, text and
// binary messages (fragmented or not), ping/pong and close. It is all the
// RTA and signaling sockets need, without a dependency.
package ws

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// Opcodes.
const (
	OpText   = 1
	OpBinary = 2
	opClose  = 8
	opPing   = 9
	opPong   = 10
)

// MaxMessage bounds a reassembled message.
const MaxMessage = 1 << 20

// Conn is one server-side websocket.
type Conn struct {
	c  net.Conn
	br *bufio.Reader
	wm sync.Mutex
	// Protocol is the negotiated subprotocol ("" when none).
	Protocol string
}

// IsUpgrade reports whether r asks for a websocket.
func IsUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// Accept completes the handshake. protocols are offered in preference order;
// when the client asks for subprotocols, the first match is selected (none
// matching still upgrades, without a Sec-WebSocket-Protocol header).
func Accept(w http.ResponseWriter, r *http.Request, protocols ...string) (*Conn, error) {
	if !IsUpgrade(r) || r.Header.Get("Sec-WebSocket-Version") != "13" {
		http.Error(w, "websocket upgrade required", http.StatusBadRequest)
		return nil, errors.New("ws: not an upgrade")
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.Error(w, "missing key", http.StatusBadRequest)
		return nil, errors.New("ws: no key")
	}
	var chosen string
	asked := map[string]bool{}
	for _, p := range strings.Split(r.Header.Get("Sec-WebSocket-Protocol"), ",") {
		if p = strings.TrimSpace(p); p != "" {
			asked[p] = true
		}
	}
	for _, p := range protocols {
		if asked[p] {
			chosen = p
			break
		}
	}
	h, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "no hijack", http.StatusInternalServerError)
		return nil, errors.New("ws: hijack unsupported")
	}
	sum := sha1.Sum([]byte(key + guid))
	nc, rw, err := h.Hijack()
	if err != nil {
		return nil, err
	}
	resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " +
		base64.StdEncoding.EncodeToString(sum[:]) + "\r\n"
	if chosen != "" {
		resp += "Sec-WebSocket-Protocol: " + chosen + "\r\n"
	}
	resp += "\r\n"
	if _, err := rw.WriteString(resp); err != nil {
		nc.Close()
		return nil, err
	}
	if err := rw.Flush(); err != nil {
		nc.Close()
		return nil, err
	}
	nc.SetDeadline(time.Time{})
	return &Conn{c: nc, br: rw.Reader, Protocol: chosen}, nil
}

// Read returns the next data message (pings are answered, pongs ignored).
func (c *Conn) Read() (op int, msg []byte, err error) {
	var buf []byte
	first := 0
	for {
		fin, opc, payload, err := c.frame()
		if err != nil {
			return 0, nil, err
		}
		switch opc {
		case opPing:
			c.write(opPong, payload)
			continue
		case opPong:
			continue
		case opClose:
			c.write(opClose, payload)
			return 0, nil, io.EOF
		}
		if opc != 0 {
			first = int(opc)
		}
		buf = append(buf, payload...)
		if len(buf) > MaxMessage {
			return 0, nil, errors.New("ws: message too large")
		}
		if fin {
			return first, buf, nil
		}
	}
}

func (c *Conn) frame() (fin bool, op byte, payload []byte, err error) {
	var h [2]byte
	if _, err = io.ReadFull(c.br, h[:]); err != nil {
		return
	}
	fin, op = h[0]&0x80 != 0, h[0]&0x0f
	masked := h[1]&0x80 != 0
	n := uint64(h[1] & 0x7f)
	switch n {
	case 126:
		var b [2]byte
		if _, err = io.ReadFull(c.br, b[:]); err != nil {
			return
		}
		n = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err = io.ReadFull(c.br, b[:]); err != nil {
			return
		}
		n = binary.BigEndian.Uint64(b[:])
	}
	if n > MaxMessage {
		err = errors.New("ws: frame too large")
		return
	}
	var mask [4]byte
	if masked {
		if _, err = io.ReadFull(c.br, mask[:]); err != nil {
			return
		}
	}
	payload = make([]byte, n)
	if _, err = io.ReadFull(c.br, payload); err != nil {
		return
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return
}

// WriteText sends one text message.
func (c *Conn) WriteText(b []byte) error { return c.write(OpText, b) }

// Ping sends a ping.
func (c *Conn) Ping() error { return c.write(opPing, nil) }

func (c *Conn) write(op byte, b []byte) error {
	c.wm.Lock()
	defer c.wm.Unlock()
	h := []byte{0x80 | op}
	switch n := len(b); {
	case n < 126:
		h = append(h, byte(n))
	case n < 1<<16:
		h = append(h, 126, byte(n>>8), byte(n))
	default:
		h = append(h, 127)
		h = binary.BigEndian.AppendUint64(h, uint64(n))
	}
	c.c.SetWriteDeadline(time.Now().Add(15 * time.Second))
	if _, err := c.c.Write(append(h, b...)); err != nil {
		return err
	}
	return nil
}

// Close closes the socket (with a close frame, best effort).
func (c *Conn) Close() error {
	c.write(opClose, []byte{0x03, 0xe8})
	return c.c.Close()
}

// RemoteAddr is the peer address.
func (c *Conn) RemoteAddr() net.Addr { return c.c.RemoteAddr() }
