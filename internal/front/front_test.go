package front

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"
)

func selfSigned(t *testing.T) tls.Certificate {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "login.live.com"},
		DNSNames: []string{"login.live.com", "*.xboxlive.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

func TestSplitByClientHello(t *testing.T) {
	// Legacy backend: records what arrives.
	legacy, _ := net.Listen("tcp", "127.0.0.1:0")
	defer legacy.Close()
	got := make(chan byte, 4)
	go func() {
		for {
			c, err := legacy.Accept()
			if err != nil {
				return
			}
			b := make([]byte, 1)
			io.ReadFull(c, b)
			got <- b[0]
			c.Close()
		}
	}()
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	f := Listen(l, &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}, NextProtos: []string{"http/1.1"}},
		map[string]string{"login.live.com": legacy.Addr().String()}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer f.Close()
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("modern")) })}
	go srv.Serve(f)
	defer srv.Close()

	// XAM-like hello: RSA key exchange only, TLS 1.2 -> spliced.
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(c, &tls.Config{ServerName: "login.live.com", InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA}})
	go tc.Handshake()
	select {
	case b := <-got:
		if b != 0x16 {
			t.Fatalf("legacy got %x", b)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RSA-only hello was not spliced")
	}
	c.Close()

	// Modern hello on the same name -> terminated here.
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{ServerName: "login.live.com", InsecureSkipVerify: true}}}
	resp, err := cl.Get("https://" + l.Addr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "modern" {
		t.Fatalf("modern got %q", b)
	}
	// A legacy-looking hello for a name without a legacy backend is terminated (and fails the
	// handshake here only because our test cert is ECDSA).
	select {
	case <-got:
		t.Fatal("unexpected splice")
	default:
	}
}
