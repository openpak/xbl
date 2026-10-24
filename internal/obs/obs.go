// Package obs logs every request a console makes, so the next missing piece
// is visible in the service log: method, host, path, status, time, header
// names and the request's JSON keys. With Bodies set it also logs request and
// response bodies with credential fields redacted (for test accounts only).
package obs

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Logger wraps a handler.
type Logger struct {
	Log    *slog.Logger
	Bodies bool
	Next   http.Handler
}

type recorder struct {
	http.ResponseWriter
	status int
	n      int
	body   *bytes.Buffer
}

func (r *recorder) WriteHeader(s int) {
	if r.status == 0 {
		r.status = s
	}
	r.ResponseWriter.WriteHeader(s)
}

func (r *recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = 200
	}
	if r.body != nil && r.body.Len() < 16<<10 {
		r.body.Write(b)
	}
	n, err := r.ResponseWriter.Write(b)
	r.n += n
	return n, err
}

// Hijack lets websocket upgrades through.
func (r *recorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("obs: hijack not supported")
	}
	if r.status == 0 {
		r.status = 101
	}
	return h.Hijack()
}

func (r *recorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (l *Logger) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	var reqBody []byte
	if r.Body != nil && r.ContentLength != 0 {
		reqBody, _ = io.ReadAll(io.LimitReader(r.Body, 256<<10))
		r.Body = io.NopCloser(bytes.NewReader(reqBody))
	}
	rec := &recorder{ResponseWriter: w}
	if l.Bodies {
		rec.body = &bytes.Buffer{}
	}
	l.Next.ServeHTTP(rec, r)
	names := make([]string, 0, len(r.Header))
	for k := range r.Header {
		names = append(names, k)
	}
	sort.Strings(names)
	attrs := []any{"method", r.Method, "host", r.Host, "path", r.URL.Path, "status", rec.status,
		"ms", time.Since(start).Milliseconds(), "in", len(reqBody), "out", rec.n, "headers", strings.Join(names, ",")}
	if q := r.URL.Query(); len(q) > 0 {
		keys := make([]string, 0, len(q))
		for k := range q {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		attrs = append(attrs, "query", strings.Join(keys, ","))
	}
	if v := r.Header.Get("x-xbl-contract-version"); v != "" {
		attrs = append(attrs, "contract", v)
	}
	if l.Bodies {
		if r.URL.RawQuery != "" {
			attrs = append(attrs, "rawquery", Redact([]byte(r.URL.RawQuery)))
		}
		if len(reqBody) > 0 {
			attrs = append(attrs, "req", Redact(reqBody))
		}
		if rec.body != nil && rec.body.Len() > 0 {
			attrs = append(attrs, "resp", Redact(rec.body.Bytes()))
		}
	} else if len(reqBody) > 0 {
		attrs = append(attrs, "keys", jsonKeys(reqBody))
	}
	l.Log.Info("request", attrs...)
}

func jsonKeys(b []byte) string {
	var m map[string]json.RawMessage
	if json.Unmarshal(b, &m) != nil {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

var secretKey = regexp.MustCompile(`(?i)token|ticket|password|secret|signature|proofkey|refresh|device_code|code_verifier|access|credential`)

// Redact returns a body with credential-looking JSON values replaced; a body
// that is not JSON is returned with long base64-looking runs elided.
func Redact(b []byte) string {
	var v any
	if json.Unmarshal(b, &v) != nil {
		if q, err := url.ParseQuery(string(b)); err == nil && strings.Contains(string(b), "=") && !strings.ContainsAny(string(b), " {<") {
			for k := range q {
				if secretKey.MatchString(k) || k == "code" || k == "otp" {
					q[k] = []string{"<redacted>"}
				}
			}
			return q.Encode()
		}
		s := string(b)
		if len(s) > 4096 {
			s = s[:4096] + "..."
		}
		return longRun.ReplaceAllString(s, "<redacted>")
	}
	out, _ := json.Marshal(redact(v, ""))
	if len(out) > 8192 {
		return string(out[:8192]) + "..."
	}
	return string(out)
}

var longRun = regexp.MustCompile(`[A-Za-z0-9_\-.=+/]{32,}`)

func redact(v any, key string) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			t[k] = redact(x, k)
		}
		return t
	case []any:
		for i, x := range t {
			t[i] = redact(x, key)
		}
		return t
	case string:
		if key != "" && secretKey.MatchString(key) {
			return "<redacted>"
		}
		return longRun.ReplaceAllString(t, "<redacted>")
	}
	return v
}
