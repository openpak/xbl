# Deploy: xbl

## Listeners

| Port | Use |
| --- | --- |
| 23510 | plain HTTP, for a front that terminates TLS itself |
| 23511 | TLS (Traefik passes the names through). A ClientHello for a name listed in `XBL_LEGACY` that offers neither ECDHE nor TLS 1.3 (the Xbox 360's XAM) is spliced unchanged to that name's legacy backend |
| 23512 | `GET /health` |
| 23513 | private approval API for the website's `/link` page (never routed publicly; `X-Internal-Key`): `GET /internal/v1/link/{user_code}` and `POST /internal/v1/link/approve {"user_code","account_id"}`; a 404 for a code carries `reason`: `unknown`, `expired` or `used` |

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `XBL_HTTP_ADDR` | `:23510` | plain HTTP listener (`off` disables) |
| `XBL_TLS_ADDR` | unset | TLS listener |
| `XBL_TLS_CERT`, `XBL_TLS_KEY` | `/app/tls/xbl.pem`, `/app/tls/xbl.key` | leaf (+CA) for the served names |
| `XBL_LEGACY` | unset | `sni=host:port,...` legacy backends for shared names |
| `XBL_HEALTH_ADDR` | `:23512` | health listener |
| `XBL_INTERNAL_ADDR` | `:23513` | private approval API (`off` disables) |
| `XBL_INTERNAL_KEY` | `WEBSITE_INTERNAL_KEY` | key the approval API requires |
| `XBL_STATE_DIR` | `/app/state` | token key, XUID map |
| `XBL_CORE_URL` | `http://openpak-account:20001` | account core gRPC |
| `XBL_CORE_KEY` | `CORE_INTERNAL_KEY` | account core internal key |
| `XBL_LINK_URL` | `https://openpak.org/link` | shown to the console as the verification URI |
| `XBL_LINK_REDIRECT` | unset | set (e.g. `https://openpak.org/link`): the public `/link` form becomes a 302 to that page with `?code=`; the website signs the person in and approves through the private API |
| `XBL_TITLES` | `000000004426B87D=1739375565` | MSA client id to Xbox title id |
| `XBL_OBSERVE_BODIES` | unset | `1` logs request/response bodies with credentials redacted (test accounts only) |

## Build and test

```sh
GOWORK=off go test -race ./...
GOWORK=off go vet ./...
podman build -t localhost/openpak-xbl:local .
```

An example quadlet is in [deploy/openpak-xbl.container](../deploy/openpak-xbl.container).
