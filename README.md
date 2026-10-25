# Xbox Network Server

OpenPak's Xbox Network Server.

| | |
| --- | --- |
| Network | Xbox Live: XAL and XSAPI titles on Nintendo Switch, PC and phones |
| Role | Modern Xbox Live services: MSA device-code sign-in, Xbox token chain, friends, presence, MPSD sessions and RTA |
| Depends on | [`account`](https://github.com/openpak/account) (account core, gRPC) |
| Used by | [`website`](https://github.com/openpak/website) (`/link` page approval) |
| Image | `localhost/openpak-xbl:local` (built from the Dockerfile) |
| Licence | AGPL-3.0-only |

## What it serves

| Endpoint | What |
| --- | --- |
| `login.live.com`, `device.auth`, `title.auth`, `user.auth`, `xsts.auth`, `sisu.xboxlive.com` | MSA device-code sign-in and the Xbox token chain |
| `social.xboxlive.com`, `peoplehub.xboxlive.com`, `userpresence.xboxlive.com` | friends, presence |
| `sessiondirectory.xboxlive.com`, `rta.xboxlive.com` | MPSD sessions and the Real-Time Activity websocket |
| `title.mgt.xboxlive.com`, `profile.xboxlive.com`, `images-eds.xboxlive.com` | NSAL documents, profile settings, gamerpics |
| `notify.xboxlive.com` | notification endpoint registration |
| `privacy`, `userstats`, `achievements`, `client-strings`, `multiplayeractivity` | permissive or empty answers |
| `vortex-events.xboxlive.com`, `*.data.microsoft.com` | telemetry, accepted and dropped |

The full host table is in [protocol.md](docs/protocol.md).

## Run

xbl runs as a container. The shortest build command is:

```sh
podman build -t localhost/openpak-xbl:local .
```

Listeners, configuration and the example quadlet are in [deploy.md](docs/deploy.md).

## Docs

- [Protocol](docs/protocol.md)
- [Evidence](docs/evidence.md)
- [Deploy](docs/deploy.md)
- [Notes](docs/notes.md)
- [Provenance](docs/provenance.md)

## Licence

AGPL-3.0-only. See [LICENSE](LICENSE).
