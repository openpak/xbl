# Provenance

xbl was written for OpenPak from these inputs only. No Microsoft server code,
SDK binaries or proprietary documents were used.

- **Client library source, MIT.** microsoft/xbox-live-api (XSAPI), tag
  `2011_GDK_r2` and the public history before it: the request URLs, headers,
  JSON the client builds and the JSON it parses for MPSD, RTA, notifications,
  social, peoplehub, profile, presence and privacy. Reading what a public
  client sends and parses, then writing a server that satisfies it, is the
  clean-room method; no code was copied.
- **Public sign-in descriptions.** The OAuth 2.0 device authorization grant
  (RFC 8628) as Microsoft accounts implement it (`oauth20_connect.srf`,
  `oauth20_token.srf`), and the Xbox token chain (device, user, title, SISU,
  XSTS) as documented by Microsoft Learn and by open-source clients such as
  PrismarineJS/prismarine-auth (MIT).
- **The title, observed by OpenPak.** Facts about one title's client (which
  hosts it resolves, its title id and MSA client id, that its XAL compares the
  title id returned by SISU with its own configuration, and the NSAL fields it
  parses) come from the owner's own copy of the game, read for interoperability.
  Only facts are recorded here; no game code or data is in this repository.
- **OpenPak's own services.** The account core contract (gRPC) for identity,
  friends, presence and avatars. `internal/core` is derived from
  github.com/openpak/x360-common/accountcore (same owner and licence).

Tokens, identifiers and responses are xbl's own designs: tokens are opaque
HMAC-signed strings, XUIDs are derived from OpenPak account ids, privileges
grant what titles check.
