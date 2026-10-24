// Package front terminates TLS for the names xbl serves and splits a few
// names it shares with the Xbox 360 services. The 360's XAM TLS client offers
// RSA key exchange only, while a modern client (the Switch's nn::ssl, a PC)
// always offers ECDHE or TLS 1.3. A shared name's ClientHello without either
// is spliced, byte for byte, to that name's legacy backend; everything else
// is terminated here with xbl's certificate.
package front

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"
)

// Hello is the part of a ClientHello the split needs.
type Hello struct {
	SNI     string
	Modern  bool // offers an ECDHE suite or TLS 1.3
	Suites  []uint16
	Partial bool // the hello did not fit in the first record
}

// ErrNotTLS means the first bytes are not a TLS handshake record.
var ErrNotTLS = errors.New("front: not a TLS ClientHello")

// ParseHello reads a ClientHello from the first TLS record.
func ParseHello(rec []byte) (*Hello, error) {
	if len(rec) < 5 || rec[0] != 0x16 {
		return nil, ErrNotTLS
	}
	n := int(binary.BigEndian.Uint16(rec[3:5]))
	body := rec[5:]
	h := &Hello{}
	if len(body) < n {
		h.Partial = true
	} else {
		body = body[:n]
	}
	if len(body) < 4 || body[0] != 1 {
		return nil, ErrNotTLS
	}
	p := body[4:]
	take := func(k int) []byte {
		if len(p) < k {
			p = nil
			return nil
		}
		b := p[:k]
		p = p[k:]
		return b
	}
	take(2 + 32) // version, random
	if sid := take(1); sid != nil {
		take(int(sid[0]))
	}
	cs := take(2)
	if cs == nil {
		return h, nil
	}
	suites := take(int(binary.BigEndian.Uint16(cs)))
	for i := 0; i+1 < len(suites); i += 2 {
		s := binary.BigEndian.Uint16(suites[i:])
		h.Suites = append(h.Suites, s)
		if modernSuite(s) {
			h.Modern = true
		}
	}
	if cm := take(1); cm != nil {
		take(int(cm[0]))
	}
	el := take(2)
	if el == nil {
		return h, nil
	}
	ext := take(int(binary.BigEndian.Uint16(el)))
	for len(ext) >= 4 {
		typ := binary.BigEndian.Uint16(ext)
		l := int(binary.BigEndian.Uint16(ext[2:]))
		if len(ext) < 4+l {
			break
		}
		data := ext[4 : 4+l]
		ext = ext[4+l:]
		switch typ {
		case 0: // server_name
			if len(data) >= 5 && data[2] == 0 {
				nl := int(binary.BigEndian.Uint16(data[3:]))
				if len(data) >= 5+nl {
					h.SNI = strings.ToLower(strings.TrimSuffix(string(data[5:5+nl]), "."))
				}
			}
		case 43: // supported_versions
			for i := 1; i+1 < len(data); i += 2 {
				if binary.BigEndian.Uint16(data[i:]) == 0x0304 {
					h.Modern = true
				}
			}
		}
	}
	return h, nil
}

func modernSuite(s uint16) bool {
	switch {
	case s >= 0x1301 && s <= 0x1305: // TLS 1.3
		return true
	case s >= 0xC001 && s <= 0xC032: // ECDH(E) suites
		return true
	case s >= 0xC072 && s <= 0xC079, s >= 0xC086 && s <= 0xC08B, s >= 0xC0AC && s <= 0xC0AF:
		return true
	case s >= 0xCCA8 && s <= 0xCCAC: // ChaCha20 (ECDHE)
		return true
	}
	return false
}

// Front is a TLS listener that hands terminated connections to Accept.
type Front struct {
	Config *tls.Config
	// Legacy maps a shared SNI to the backend that receives non-modern hellos.
	Legacy map[string]string
	Log    *slog.Logger

	inner  net.Listener
	conns  chan net.Conn
	once   sync.Once
	closed chan struct{}
}

// Listen starts the front on l.
func Listen(l net.Listener, cfg *tls.Config, legacy map[string]string, log *slog.Logger) *Front {
	f := &Front{Config: cfg, Legacy: legacy, Log: log, inner: l, conns: make(chan net.Conn), closed: make(chan struct{})}
	go f.loop()
	return f
}

func (f *Front) loop() {
	for {
		c, err := f.inner.Accept()
		if err != nil {
			f.Close()
			return
		}
		go f.handle(c)
	}
}

type prefixConn struct {
	net.Conn
	r io.Reader
}

func (p *prefixConn) Read(b []byte) (int, error) { return p.r.Read(b) }

func (f *Front) handle(c net.Conn) {
	c.SetReadDeadline(time.Now().Add(15 * time.Second))
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c, hdr); err != nil {
		c.Close()
		return
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	if hdr[0] != 0x16 || n > 1<<14+2048 {
		c.Close()
		return
	}
	rec := make([]byte, 5+n)
	copy(rec, hdr)
	if _, err := io.ReadFull(c, rec[5:]); err != nil {
		c.Close()
		return
	}
	c.SetReadDeadline(time.Time{})
	h, err := ParseHello(rec)
	if err != nil {
		c.Close()
		return
	}
	if backend, ok := f.Legacy[h.SNI]; ok && !h.Modern {
		f.splice(c, rec, backend, h)
		return
	}
	tc := tls.Server(&prefixConn{Conn: c, r: io.MultiReader(bytes.NewReader(rec), c)}, f.Config)
	select {
	case f.conns <- tc:
	case <-f.closed:
		c.Close()
	}
}

func (f *Front) splice(c net.Conn, first []byte, backend string, h *Hello) {
	defer c.Close()
	b, err := net.DialTimeout("tcp", backend, 5*time.Second)
	if err != nil {
		f.Log.Warn("front: legacy backend unreachable", "sni", h.SNI, "err", err)
		return
	}
	defer b.Close()
	f.Log.Info("front: legacy client spliced", "sni", h.SNI)
	if _, err := b.Write(first); err != nil {
		return
	}
	// TLS never half-closes: the first side to finish ends both.
	done := make(chan struct{}, 2)
	go func() { io.Copy(b, c); done <- struct{}{} }()
	go func() { io.Copy(c, b); done <- struct{}{} }()
	<-done
}

// Accept returns the next terminated connection.
func (f *Front) Accept() (net.Conn, error) {
	select {
	case c := <-f.conns:
		return c, nil
	case <-f.closed:
		return nil, net.ErrClosed
	}
}

// Close stops the front.
func (f *Front) Close() error {
	f.once.Do(func() { close(f.closed); f.inner.Close() })
	return nil
}

// Addr is the listening address.
func (f *Front) Addr() net.Addr { return f.inner.Addr() }
