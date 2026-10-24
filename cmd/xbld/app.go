package main

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/openpak/xbl/internal/core"
	"github.com/openpak/xbl/internal/ident"
	"github.com/openpak/xbl/internal/mpsd"
	"github.com/openpak/xbl/internal/msa"
	"github.com/openpak/xbl/internal/rta"
	"github.com/openpak/xbl/internal/svc"
	"github.com/openpak/xbl/internal/token"
	"github.com/openpak/xbl/internal/xauth"
)

// Core is the account-core surface the services use.
type Core interface {
	VerifyPassword(ctx context.Context, email, password string) (*core.Verified, error)
	VerifySecondFactor(ctx context.Context, accountID, code string) error
	GetAccount(ctx context.Context, account string) (*core.Account, error)
	ListFriends(ctx context.Context, account string) ([]core.Friend, error)
	CanDiscover(ctx context.Context, account, other string) (bool, error)
	GetPresence(ctx context.Context, accounts []string) (map[string]core.Presence, error)
	GetAvatar(ctx context.Context, accountID string, size uint32) ([]byte, error)
}

// App routes a request to its service by host name.
type App struct {
	Log    *slog.Logger
	Tokens *token.Signer
	Dir    *ident.Directory
	Core   Core
	MSA    *msa.Service
	Auth   *xauth.Service

	Hub    *rta.Hub
	MPSD   *mpsd.Service
	People *svc.People

	hosts map[string]http.Handler
}

func (a *App) init() {
	auth := a.Auth
	a.Hub = &rta.Hub{Log: a.Log, Auth: func(r *http.Request) (*rta.Caller, error) {
		c, err := auth.Authenticate(r)
		if err != nil {
			return nil, err
		}
		return &rta.Caller{Account: c.Account, XUID: c.XUID}, nil
	}}
	a.MPSD = &mpsd.Service{Dir: a.Dir, Hub: a.Hub, Log: a.Log, MaxMembers: 4,
		Auth: func(r *http.Request) (*mpsd.Caller, error) {
			c, err := auth.Authenticate(r)
			if err != nil {
				return nil, err
			}
			return &mpsd.Caller{Account: c.Account, XUID: c.XUID, Title: c.Title}, nil
		},
		Friends: func(ctx context.Context, account string) ([]string, error) {
			fs, err := a.Core.ListFriends(ctx, account)
			ids := make([]string, 0, len(fs))
			for _, f := range fs {
				ids = append(ids, f.AccountID)
			}
			return ids, err
		},
	}
	a.People = &svc.People{Dir: a.Dir, Core: a.Core, Hub: a.Hub, Log: a.Log,
		TitleName: map[string]string{"1739375565": "Minecraft Dungeons"},
		Auth: func(r *http.Request) (*svc.Caller, error) {
			c, err := auth.Authenticate(r)
			if err != nil {
				return nil, err
			}
			return &svc.Caller{Account: c.Account, XUID: c.XUID, Title: c.Title}, nil
		},
	}
	a.Hub.Resources = []rta.Resource{
		func(c *rta.Conn, uri string) (any, bool) {
			if strings.HasPrefix(strings.ToLower(uri), "https://sessiondirectory.xboxlive.com/connections") {
				return map[string]any{"ConnectionId": c.ID}, true
			}
			return nil, false
		},
		a.People.PresenceResource,
	}
	a.Hub.OnClose = func(c *rta.Conn) { a.MPSD.ConnectionClosed(c.ID) }
	p := a.People
	a.hosts = map[string]http.Handler{
		"rta.xboxlive.com":                 a.Hub,
		"sessiondirectory.xboxlive.com":    a.MPSD,
		"profile.xboxlive.com":             http.HandlerFunc(p.Profile),
		"social.xboxlive.com":              http.HandlerFunc(p.Social),
		"peoplehub.xboxlive.com":           http.HandlerFunc(p.PeopleHub),
		"userpresence.xboxlive.com":        http.HandlerFunc(p.Presence),
		"privacy.xboxlive.com":             http.HandlerFunc(p.Privacy),
		"notify.xboxlive.com":              http.HandlerFunc(p.Notify),
		"images-eds.xboxlive.com":          http.HandlerFunc(p.Image),
		"userstats.xboxlive.com":           http.HandlerFunc(p.Empty),
		"statswrite.xboxlive.com":          http.HandlerFunc(p.Empty),
		"achievements.xboxlive.com":        http.HandlerFunc(p.Empty),
		"titlestorage.xboxlive.com":        http.HandlerFunc(p.Empty),
		"client-strings.xboxlive.com":      http.HandlerFunc(p.Empty),
		"multiplayeractivity.xboxlive.com": http.HandlerFunc(p.Empty),
		"leaderboards.xboxlive.com":        http.HandlerFunc(p.Empty),
		"login.live.com":                   a.MSA,
		"device.auth.xboxlive.com":         auth,
		"title.auth.xboxlive.com":          auth,
		"user.auth.xboxlive.com":           auth,
		"xsts.auth.xboxlive.com":           auth,
		"sisu.xboxlive.com":                auth,
		"title.mgt.xboxlive.com":           auth,
		"vortex-events.xboxlive.com":       http.HandlerFunc(svc.Sink),
		"vortex.data.microsoft.com":        http.HandlerFunc(svc.Sink),
		"vortex-win.data.microsoft.com":    http.HandlerFunc(svc.Sink),
		"settings.data.microsoft.com":      http.HandlerFunc(svc.Sink),
	}
}

// host is the request's host name, lower case, without a port.
func host(r *http.Request) string {
	h := r.Host
	if i := strings.LastIndexByte(h, ':'); i >= 0 && !strings.Contains(h[i:], "]") {
		h = h[:i]
	}
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := host(r)
	if hd, ok := a.hosts[h]; ok {
		hd.ServeHTTP(w, r)
		return
	}
	// The approval page answers on any public name routed here.
	if p := strings.ToLower(r.URL.Path); p == "/link" || p == "/link/" || strings.HasPrefix(p, "/xbox/link") {
		a.MSA.ServeHTTP(w, r)
		return
	}
	a.Log.Warn("unhandled host", "host", h, "method", r.Method, "path", r.URL.Path)
	svc.WriteJSON(w, http.StatusNotFound, map[string]any{"code": "NotFound", "description": "not served by OpenPak"})
}
