// Command xbld serves the modern Xbox network services (the ones XAL and
// XSAPI titles call on Switch, PC and phones) for OpenPak accounts.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/openpak/xbl/internal/core"
	"github.com/openpak/xbl/internal/front"
	"github.com/openpak/xbl/internal/ident"
	"github.com/openpak/xbl/internal/msa"
	"github.com/openpak/xbl/internal/obs"
	"github.com/openpak/xbl/internal/token"
	"github.com/openpak/xbl/internal/xauth"
)

var version = "dev"

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// pairs parses "a=b,c=d".
func pairs(s string) map[string]string {
	m := map[string]string{}
	for _, p := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
		if ok && k != "" && v != "" {
			m[strings.ToLower(k)] = v
		}
	}
	return m
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck(env("XBL_HEALTH_ADDR", "127.0.0.1:23502")))
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("xbld", "err", err)
		os.Exit(1)
	}
}

func healthcheck(addr string) int {
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	c := http.Client{Timeout: 3 * time.Second}
	r, err := c.Get("http://" + addr + "/health")
	if err != nil || r.StatusCode != 200 {
		return 1
	}
	return 0
}

func run(log *slog.Logger) error {
	state := env("XBL_STATE_DIR", "/app/state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		return err
	}
	key := env("XBL_CORE_KEY", os.Getenv("CORE_INTERNAL_KEY"))
	cc, err := core.New(env("XBL_CORE_URL", "http://openpak-account:20001"), key, nil)
	if err != nil {
		return err
	}
	tokens, err := token.Open(state)
	if err != nil {
		return err
	}
	dir, err := ident.Open(cc, state)
	if err != nil {
		return err
	}
	titles := map[string]string{}
	for k, v := range pairs(env("XBL_TITLES", "000000004426B87D=1739375565")) {
		titles[strings.ToUpper(k)] = v
	}
	app := &App{
		Log:    log,
		Tokens: tokens,
		Dir:    dir,
		Core:   cc,
		MSA:    msa.New(cc, tokens, log, env("XBL_LINK_URL", "https://openpak.org/link")),
		Auth:   &xauth.Service{Tokens: tokens, Dir: dir, Log: log, Titles: titles, DefaultTitle: env("XBL_DEFAULT_TITLE", "1739375565")},
	}
	app.init()
	handler := &obs.Logger{Log: log, Bodies: os.Getenv("XBL_OBSERVE_BODIES") == "1", Next: app}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 4)
	var servers []*http.Server
	serve := func(name string, l net.Listener, h http.Handler) {
		srv := &http.Server{Handler: h, ReadHeaderTimeout: 15 * time.Second, IdleTimeout: 120 * time.Second}
		servers = append(servers, srv)
		log.Info("listening", "listener", name, "addr", l.Addr().String(), "version", version)
		go func() {
			if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}()
	}
	if addr := env("XBL_HTTP_ADDR", ":23500"); addr != "off" {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		serve("http", l, handler)
	}
	if addr := os.Getenv("XBL_TLS_ADDR"); addr != "" {
		cert, err := tls.LoadX509KeyPair(env("XBL_TLS_CERT", "/app/tls/xbl.pem"), env("XBL_TLS_KEY", "/app/tls/xbl.key"))
		if err != nil {
			return err
		}
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
		serve("tls", front.Listen(l, cfg, pairs(os.Getenv("XBL_LEGACY")), log), handler)
	}
	hl, err := net.Listen("tcp", env("XBL_HEALTH_ADDR", ":23502"))
	if err != nil {
		return err
	}
	hm := http.NewServeMux()
	hm.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	serve("health", hl, hm)

	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			for _, s := range servers {
				s.Shutdown(sctx)
			}
			cancel()
			return dir.Flush()
		case err := <-errc:
			return err
		case <-tick.C:
			if err := dir.Flush(); err != nil {
				log.Error("ident flush", "err", err)
			}
		}
	}
}
