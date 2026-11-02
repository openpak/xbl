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

## Scope and sources

xbl serves the modern Xbox services that titles built on Microsoft's XAL (sign-in) and XSAPI (social, presence, multiplayer) call, on Nintendo Switch, PC and phones. An OpenPak account is presented as a Microsoft account with an Xbox identity: an XUID derived from the account id and the account's handle as gamertag. Friends and blocks are the account core's. First title: Minecraft Dungeons on Switch (`01006C100EC08000`, Xbox title `1739375565`).

Not affiliated with or endorsed by Microsoft. Written clean-room from the public MIT-licensed client library (microsoft/xbox-live-api, tag `2011_GDK_r2`), public sign-in descriptions (RFC 8628 device grant; the device/user/title/SISU/XSTS token chain as documented by Microsoft Learn and PrismarineJS/prismarine-auth, MIT), and facts read from the owner's own copy of the title for interoperability (hosts it resolves, title id and MSA client id, that its XAL compares the SISU-returned title id with its own configuration, the NSAL fields it parses). No Microsoft server code, SDK binaries or proprietary documents were used. Tokens are opaque HMAC-signed strings; `internal/core` is derived from github.com/openpak/x360-common/accountcore (same owner and licence).
