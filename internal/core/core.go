// Package core is a dependency-free client for the OpenPak account core's
// gRPC API (Identity, Social, Sessions), speaking the gRPC wire format over
// net/http: the five-byte message frame, application/grpc and the
// grpc-status trailer. Only the messages xbl needs are encoded.
//
// Derived from github.com/openpak/x360-common/accountcore (same owner, same
// licence, AGPL-3.0-only), trimmed to xbl's calls.
package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	identityService = "/openpak.account.v1.Identity/"
	socialService   = "/openpak.account.v1.Social/"
	sessionsService = "/openpak.account.v1.Sessions/"
)

// gRPC status codes the callers care about.
const (
	CodeNotFound        = 5
	CodeFailedPrecond   = 9
	CodeUnauthenticated = 16
)

// StatusActive is openpak.account.v1.AccountStatus ACTIVE.
const StatusActive = 1

// Error is a non-OK gRPC status.
type Error struct {
	Code    int
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("account core: grpc status %d: %s", e.Code, e.Message)
}

// IsCode reports whether err is a gRPC status with the given code.
func IsCode(err error, code int) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == code
}

// ErrInactive means the account is not active (banned, deleted, unknown).
var ErrInactive = errors.New("account is not active")

// Client talks to one account core. Zero Timeout means 5 seconds per call.
type Client struct {
	base    string
	token   string
	http    *http.Client
	Timeout time.Duration
}

// New builds a client for the core's gRPC listener (http://host:port over
// cleartext HTTP/2, or https://). token is the internal key.
func New(baseURL, token string, hc *http.Client) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("account core URL must be http(s)://host:port, got %q", baseURL)
	}
	if token == "" {
		return nil, errors.New("account core token is required")
	}
	if hc == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.Protocols = new(http.Protocols)
		tr.Protocols.SetHTTP2(true)
		tr.Protocols.SetUnencryptedHTTP2(true)
		hc = &http.Client{Transport: tr}
	}
	return &Client{base: strings.TrimRight(baseURL, "/"), token: token, http: hc}, nil
}

// Verified is a successful password check.
type Verified struct {
	AccountID         string
	Status            int
	TwoFactorRequired bool
}

// VerifyPassword checks an OpenPak email and password (caller namespace
// "xbl", purpose "device_link"). The caller supports a second factor: when
// the account has one, TwoFactorRequired is set and VerifySecondFactor is
// owed before the person counts as signed in.
func (c *Client) VerifyPassword(ctx context.Context, email, password string) (*Verified, error) {
	var req pb
	req.str(1, "xbl")
	req.str(2, "device_link")
	req.str(3, email)
	req.str(4, password)
	req = append(req, 5<<3, 1)
	resp, err := c.call(ctx, identityService+"VerifyPassword", req)
	if err != nil {
		return nil, err
	}
	f := parseFields(resp)
	return &Verified{AccountID: f.str(1), Status: int(f.num(2)), TwoFactorRequired: f.num(6) == 1}, nil
}

// VerifySecondFactor completes a password check for a two-factor account.
func (c *Client) VerifySecondFactor(ctx context.Context, accountID, code string) error {
	var req pb
	req.str(1, accountID)
	req.str(2, code)
	_, err := c.call(ctx, identityService+"VerifySecondFactor", req)
	return err
}

// Account is the part of GetAccount xbl reads.
type Account struct {
	ID          string
	DisplayName string
	Country     string
	Handle      string
	Bio, Motto  string
}

// GetAccount reads an active account (fields 1 id, 2 status, 4 display name,
// 5 country, 9 handle, 10 bio, 11 motto).
func (c *Client) GetAccount(ctx context.Context, account string) (*Account, error) {
	var req pb
	req.str(1, account)
	resp, err := c.call(ctx, identityService+"GetAccount", req)
	if IsCode(err, CodeNotFound) {
		return nil, ErrInactive
	}
	if err != nil {
		return nil, err
	}
	f := parseFields(resp)
	if f.str(1) != account || f.num(2) != StatusActive {
		return nil, ErrInactive
	}
	return &Account{ID: account, DisplayName: f.str(4), Country: f.str(5), Handle: f.str(9), Bio: f.str(10), Motto: f.str(11)}, nil
}

// Friend is one accepted friendship.
type Friend struct {
	AccountID   string
	DisplayName string
}

// ListFriends returns the account's accepted friends.
func (c *Client) ListFriends(ctx context.Context, account string) ([]Friend, error) {
	var req pb
	req.str(1, account)
	resp, err := c.call(ctx, socialService+"ListFriends", req)
	if err != nil {
		return nil, err
	}
	msgs, err := repeated(resp, 1)
	if err != nil {
		return nil, err
	}
	out := make([]Friend, 0, len(msgs))
	for _, m := range msgs {
		f := parseFields(m)
		if f.str(1) == "" {
			return nil, errors.New("account core: social entry has no account id")
		}
		out = append(out, Friend{AccountID: f.str(1), DisplayName: f.str(2)})
	}
	return out, nil
}

// CanDiscover applies the core's friendship, block and active-account rules
// (CheckInteraction, kind DISCOVER).
func (c *Client) CanDiscover(ctx context.Context, account, other string) (bool, error) {
	var req pb
	req.str(1, account)
	req.str(2, other)
	req = append(req, 0x18, 0x01)
	resp, err := c.call(ctx, socialService+"CheckInteraction", req)
	if err != nil {
		return false, err
	}
	return parseFields(resp).num(1) == 1, nil
}

// RegisterSession opens (or replaces) the account's presence lease in a
// namespace and title; an empty title means signed in, not in a game.
func (c *Client) RegisterSession(ctx context.Context, accountID, namespace, titleID, endpointRef string, leaseSeconds int, client, os string) (string, int, error) {
	var req pb
	req.str(1, accountID)
	req.str(2, namespace)
	req.str(3, titleID)
	req.str(4, endpointRef)
	if leaseSeconds > 0 {
		req = binary.AppendUvarint(req, 5<<3)
		req = binary.AppendUvarint(req, uint64(leaseSeconds))
	}
	req.str(6, client)
	req.str(7, os)
	resp, err := c.call(ctx, sessionsService+"RegisterSession", req)
	if err != nil {
		return "", 0, err
	}
	f := parseFields(resp)
	return f.str(1), int(f.num(2)), nil
}

// Heartbeat renews a lease; an error means it lapsed.
func (c *Client) Heartbeat(ctx context.Context, sessionID string) error {
	var req pb
	req.str(1, sessionID)
	_, err := c.call(ctx, sessionsService+"Heartbeat", req)
	return err
}

// ExpireSession ends a lease.
func (c *Client) ExpireSession(ctx context.Context, sessionID string) error {
	var req pb
	req.str(1, sessionID)
	_, err := c.call(ctx, sessionsService+"ExpireSession", req)
	return err
}

// Presence is one account's live session as the core reports it.
type Presence struct {
	Namespace string
	TitleID   string
	Since     int64
}

// GetPresence reads the presence of accounts (request: repeated account_ids
// = 1; response: repeated Presence = 1 {1 account_id, 2 namespace, 3
// title_id, 4 since_unix}, only accounts with a live session).
func (c *Client) GetPresence(ctx context.Context, accounts []string) (map[string]Presence, error) {
	var req pb
	for _, a := range accounts {
		req.str(1, a)
	}
	resp, err := c.call(ctx, sessionsService+"GetPresence", req)
	if err != nil {
		return nil, err
	}
	msgs, err := repeated(resp, 1)
	if err != nil {
		return nil, err
	}
	out := map[string]Presence{}
	for _, m := range msgs {
		f := parseFields(m)
		out[f.str(1)] = Presence{Namespace: f.str(2), TitleID: f.str(3), Since: int64(f.num(4))}
	}
	return out, nil
}

func (c *Client) call(ctx context.Context, method string, req pb) ([]byte, error) {
	d := c.Timeout
	if d == 0 {
		d = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	frame := make([]byte, 5, 5+len(req))
	binary.BigEndian.PutUint32(frame[1:], uint32(len(req)))
	frame = append(frame, req...)
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+method, bytes.NewReader(frame))
	if err != nil {
		return nil, err
	}
	hr.Header.Set("Content-Type", "application/grpc")
	hr.Header.Set("TE", "trailers")
	hr.Header.Set("X-Internal-Key", c.token)
	resp, err := c.http.Do(hr)
	if err != nil {
		return nil, fmt.Errorf("account core: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("account core: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("account core: http status %d", resp.StatusCode)
	}
	st, msg := resp.Trailer.Get("Grpc-Status"), resp.Trailer.Get("Grpc-Message")
	if st == "" {
		st, msg = resp.Header.Get("Grpc-Status"), resp.Header.Get("Grpc-Message")
	}
	if st == "" {
		return nil, errors.New("account core: response without grpc-status")
	}
	code, err := strconv.Atoi(st)
	if err != nil {
		return nil, errors.New("account core: bad grpc-status")
	}
	if code != 0 {
		return nil, &Error{Code: code, Message: msg}
	}
	if len(body) < 5 || body[0] != 0 {
		return nil, errors.New("account core: bad message frame")
	}
	if n := binary.BigEndian.Uint32(body[1:5]); int(n) != len(body)-5 {
		return nil, errors.New("account core: bad message length")
	}
	return body[5:], nil
}

// pb is a protobuf message under construction.
type pb []byte

func (p *pb) str(field int, s string) {
	if s == "" {
		return
	}
	*p = binary.AppendUvarint(*p, uint64(field)<<3|2)
	*p = binary.AppendUvarint(*p, uint64(len(s)))
	*p = append(*p, s...)
}

type fields struct {
	s map[int]string
	n map[int]uint64
}

func (f fields) str(i int) string { return f.s[i] }
func (f fields) num(i int) uint64 { return f.n[i] }

// parseFields reads the string and varint fields of a message and skips the
// rest; a malformed tail stops the parse.
func parseFields(b []byte) fields {
	f := fields{s: map[int]string{}, n: map[int]uint64{}}
	for len(b) > 0 {
		tag, n := binary.Uvarint(b)
		if n <= 0 {
			break
		}
		b = b[n:]
		field := int(tag >> 3)
		switch tag & 7 {
		case 0:
			v, n := binary.Uvarint(b)
			if n <= 0 {
				return f
			}
			f.n[field] = v
			b = b[n:]
		case 2:
			l, n := binary.Uvarint(b)
			if n <= 0 || uint64(len(b)-n) < l {
				return f
			}
			f.s[field] = string(b[n : n+int(l)])
			b = b[n+int(l):]
		case 1:
			if len(b) < 8 {
				return f
			}
			b = b[8:]
		case 5:
			if len(b) < 4 {
				return f
			}
			b = b[4:]
		default:
			return f
		}
	}
	return f
}

// repeated returns every embedded message in field `want`, rejecting
// malformed framing rather than reading a truncated list as a short one.
func repeated(b []byte, want int) ([][]byte, error) {
	var out [][]byte
	for len(b) > 0 {
		tag, n := binary.Uvarint(b)
		if n <= 0 || tag>>3 == 0 {
			return nil, errors.New("account core: malformed response")
		}
		b = b[n:]
		switch tag & 7 {
		case 0:
			if _, n = binary.Uvarint(b); n <= 0 {
				return nil, errors.New("account core: malformed varint")
			}
			b = b[n:]
		case 1, 5:
			size := 8
			if tag&7 == 5 {
				size = 4
			}
			if len(b) < size {
				return nil, errors.New("account core: truncated field")
			}
			b = b[size:]
		case 2:
			size, n := binary.Uvarint(b)
			if n <= 0 || size > uint64(len(b)-n) {
				return nil, errors.New("account core: truncated message")
			}
			if int(tag>>3) == want {
				out = append(out, b[n:n+int(size)])
			}
			b = b[n+int(size):]
		default:
			return nil, errors.New("account core: unsupported wire type")
		}
	}
	return out, nil
}

// GetAvatar fetches the account's 256 px PNG; a missing avatar is
// CodeNotFound.
func (c *Client) GetAvatar(ctx context.Context, accountID string, size uint32) ([]byte, error) {
	var req pb
	req.str(1, accountID)
	req = binary.AppendUvarint(req, 2<<3)
	req = binary.AppendUvarint(req, uint64(size))
	resp, err := c.call(ctx, "/openpak.account.v1.Media/GetAvatar", req)
	if err != nil {
		return nil, err
	}
	return []byte(parseFields(resp).str(1)), nil
}
