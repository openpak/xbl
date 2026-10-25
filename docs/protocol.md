# Protocol: xbl

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
