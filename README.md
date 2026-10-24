# xbl

The modern Xbox network services for OpenPak: the services that titles built
on Microsoft's XAL (sign-in) and XSAPI (social, presence, multiplayer)
libraries call, on Nintendo Switch, PC and phones. An OpenPak account is
presented to the title as a Microsoft account with an Xbox identity: an XUID
derived from the account, and the account's handle as its gamertag. Friends
and blocks are the account core's.

First title: Minecraft Dungeons on Switch (`01006C100EC08000`, Xbox title
`1739375565`).

Not affiliated with or endorsed by Microsoft. Written from public protocol
documentation and the public, MIT-licensed client library source; see
[docs/provenance.md](docs/provenance.md).

## What it serves

| Host | What |
| --- | --- |
| `login.live.com` | MSA remote-connect sign-in: `/oauth20_connect.srf` (device code), `/oauth20_token.srf` (device code and refresh grants), and `/link`, the page where a person enters the console's code with their OpenPak email and password (two-factor supported) |
| `device.auth`, `title.auth`, `user.auth`, `xsts.auth`, `sisu.xboxlive.com` | device token, title and user tokens, SISU authorize, XSTS for any relying party |
| `title.mgt.xboxlive.com` | NSAL documents (default and per title) |
| `profile.xboxlive.com` | profile settings (single, batch, social group) |
| `social.xboxlive.com`, `peoplehub.xboxlive.com` | the friend list (account core friends) with presence |
| `userpresence.xboxlive.com` | presence set/get/batch, heartbeat |
| `sessiondirectory.xboxlive.com` | MPSD: sessions, members, handles (activity, invite, transfer), activity query, shoulder taps |
| `rta.xboxlive.com` | the Real-Time Activity websocket (`rta.xboxlive.com.V2`): MPSD connection ids, session taps, game invites, presence changes |
| `notify.xboxlive.com` | notification endpoint registration |
| `privacy`, `userstats`, `achievements`, `client-strings`, `multiplayeractivity`, ... | permissive or empty answers |
| `vortex-events.xboxlive.com`, `*.data.microsoft.com` | telemetry, accepted and dropped |
| `images-eds.xboxlive.com` | gamerpics (the account's avatar) |

Tokens are xbl's own (HMAC-signed, opaque to clients). Sessions, handles and
presence are in memory; the XUID reverse map and the token key persist in the
state directory.

## Listeners

| Port | Use |
| --- | --- |
| 23510 | plain HTTP, for a front that terminates TLS itself |
| 23511 | TLS (Traefik passes the names through). A ClientHello for a name listed in `XBL_LEGACY` that offers neither ECDHE nor TLS 1.3 (the Xbox 360's XAM) is spliced unchanged to that name's legacy backend |
| 23512 | `GET /health` |

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `XBL_HTTP_ADDR` | `:23510` | plain HTTP listener (`off` disables) |
| `XBL_TLS_ADDR` | unset | TLS listener |
| `XBL_TLS_CERT`, `XBL_TLS_KEY` | `/app/tls/xbl.pem`, `/app/tls/xbl.key` | leaf (+CA) for the served names |
| `XBL_LEGACY` | unset | `sni=host:port,...` legacy backends for shared names |
| `XBL_HEALTH_ADDR` | `:23512` | health listener |
| `XBL_STATE_DIR` | `/app/state` | token key, XUID map |
| `XBL_CORE_URL` | `http://openpak-account:20001` | account core gRPC |
| `XBL_CORE_KEY` | `CORE_INTERNAL_KEY` | account core internal key |
| `XBL_LINK_URL` | `https://openpak.org/link` | shown to the console as the verification URI |
| `XBL_TITLES` | `000000004426B87D=1739375565` | MSA client id to Xbox title id |
| `XBL_OBSERVE_BODIES` | unset | `1` logs request/response bodies with credentials redacted (test accounts only) |

## Build and test

```sh
GOWORK=off go test -race ./...
GOWORK=off go vet ./...
podman build -t localhost/openpak-xbl:local .
```

An example quadlet is in [deploy/openpak-xbl.container](deploy/openpak-xbl.container).

## Licence

AGPL-3.0-only. See [LICENSE](LICENSE).
