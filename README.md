# OIDC Playground

A stateless web page for trying OpenID Connect requests: fill in the provider
and your client, pick the scopes and claims you want, authorize at the provider,
come back and inspect everything it says — the token response, the ID token
(claims, decoded JWT, raw JWT, validation checks) and the UserInfo response as
plain values.

Built for testing itsme® (sandbox or production), works with any provider that
publishes a discovery document.

```
browser  ── builds the request (state, nonce, PKCE) ──▶ <issuer>/authorization
browser  ◀── provider redirects to /callback?code=…&state=… ──
browser  ── POST /api/token  (callback URL + client details + what it remembered) ──▶ backend ──▶ token endpoint
browser  ◀── tokens, ID token claims + validation checks ──
browser  ── POST /api/userinfo (access token) ──▶ backend ──▶ userinfo endpoint ──▶ plain values
```

**Nothing is configured or stored on the server.** Issuer, client id, service code,
scopes and claims are remembered in the browser's `localStorage`; the client
secret or private key only in `sessionStorage` (this tab, until you close it).
The backend is a thin helper that does what a browser cannot: fetch the discovery
document, exchange the code (with your client credentials, per request), validate
the ID token and call the UserInfo endpoint. It keeps nothing but a short cache of
discovery documents.

## Quick start (no credentials needed)

```sh
npm install
npm run mock-op   # terminal 1: a tiny OpenID Provider on http://localhost:9000
npm start         # terminal 2: the playground on http://localhost:3000
```

Open http://localhost:3000, choose the preset **Local mock provider**, enter client
id `playground`, authentication `client_secret_post` with secret `secret`, press
**Authorize**, approve on the mock consent page and you land on the result page.
The mock persona is *Lotte Vermeulen*; it deliberately never returns `gender`, so
you can see how a requested-but-missing claim is shown.

## Against itsme®

1. itsme only accepts **https** redirect URIs: `npm run cert` (self-signed
   certificate), `cp .env.example .env`, `npm start` → https://localhost:8443.
2. Register `https://localhost:8443/callback` as a redirect URI for your client at
   itsme. For the sandbox to reach you from the outside you may need a tunnel
   (e.g. `ngrok http 8443`) — then open the page through the tunnel URL; the
   redirect URI shown in the form follows the address you opened the page on.
3. In the page: issuer preset **itsme® sandbox**, your client id and service code,
   and either the client secret (`client_secret_post`) or your **private key**
   (`private_key_jwt`) pasted as JWK or PEM.
   The matching **public** key must be in the JWKS you host on your own public
   link — the `jwks_uri` registered at itsme. The page shows the kid, alg and
   public JWK of the pasted key so you can check they match; the private key
   itself never leaves your browser tab except to sign the token request.
4. If your itsme client is configured for **encrypted** ID tokens / UserInfo, paste
   the (RSA) private key as well — encrypted responses are decrypted with it
   automatically, whatever the authentication method.

## What the page does

**1 · Build request** — provider (issuer presets: itsme sandbox, itsme production,
local mock, or any issuer) with live discovery, client id, client authentication
(`client_secret_post`, `client_secret_basic`, `private_key_jwt`, `none`), the
redirect URI to register; scopes as toggles (`openid` fixed, `service:<code>` for
itsme, `profile`, `email`, `phone`, `address`, `eid`, `offline_access`); every
standard claim from OpenID Connect Core §5.1 plus the itsme® claims (requested by
their full `http://itsme.services/v2/claim/…` URI), an *essential* flag per claim,
and a choice of delivering them in UserInfo, the ID token, or both — this becomes
the `claims` request parameter. Request options: `acr_values` (presets plus what
discovery advertises), `prompt`, `ui_locales`, `max_age`, `login_hint`, PKCE on/off.
The authorization request and the `claims` JSON are previewed live.

**2 · Authorize** — `state`, `nonce` and the PKCE verifier are generated in the
browser, remembered in the tab, and you are redirected to the provider.

**3 · Tokens & claims** — back on `/callback` the page verifies `state`, sends the
callback URL plus your client details to `/api/token`; the backend exchanges the
code (with `code_verifier`) and validates the ID token with
[openid-client](https://github.com/panva/openid-client): signature against
`jwks_uri`, `iss`, `aud`, `exp`, `iat`, `nonce`, `auth_time`/`max_age`; `at_hash`
is checked additionally. You see the token response (copyable tokens), the ID
token as *Claims* (about the user and about itself, requested-but-missing claims
marked), *Decoded* (header / payload / signature) and *Raw JWT*, the list of
checks, and the exact request that was sent.

**4 · UserInfo** — one click calls the userinfo endpoint with the access token and
shows the plain values, the raw response, a "requested vs returned" summary and
whether the values match the ID token. JSON, signed JWT and encrypted JWT
responses are all handled.

## API (what the page calls)

| route | body | returns |
| --- | --- | --- |
| `POST /api/discover` | `{ issuer }` | endpoints and capabilities from the discovery document |
| `POST /api/token` | `{ issuer, client_id, client_auth: { method, client_secret?, private_key? }, callback_url, expected_state, expected_nonce, code_verifier?, max_age? }` | `tokens`, `idToken { header, payload, checks }` |
| `POST /api/userinfo` | `{ issuer, client_id, access_token, expected_sub, private_key? }` | request/response details, `claims`, `checks` |
| `POST /api/keys/inspect` | `{ private_key }` | `kid`, `alg`, `public_jwk` of a pasted private key |

Every response is `{ ok: true, … }` or `{ ok: false, error: { error, error_description, stage } }`.
`http://` issuers are accepted for localhost only (`ALLOW_INSECURE_ISSUER=1` to override).

## Configuration (server only)

| variable | meaning |
| --- | --- |
| `PORT` | 3000, or 8443 when TLS files are set |
| `TLS_KEY_FILE`, `TLS_CERT_FILE` | serve https (see `npm run cert`) |
| `TRUST_PROXY` | `1` behind a tunnel / reverse proxy |
| `ALLOW_INSECURE_ISSUER` | allow `http://` issuers other than localhost |
| `DISCOVERY_CACHE_SECONDS` | how long discovery documents are cached (default 300) |

## Project layout

```
server/      Express backend — stateless relying-party helper
  index.js     start-up, http/https
  app.js       routes: /api/discover, /api/token, /api/userinfo, /api/keys/inspect + static page
  oidc.js      discovery cache, code exchange, ID token checks, userinfo (openid-client + jose)
  jwt.js       decoding helpers, at_hash, JWT/JWE userinfo parsing
  keys.js      pasted private key (JWK/PEM) → signing + decryption keys, public JWK
  validate.js  validation of what the page sends
  config.js    server settings
public/      the page (no build step)
  js/catalog.js  presets, scopes, standard + itsme claims, request builders (shared with tests)
  js/app.js      request builder, /callback handling, result page
tools/
  mock-op.js   minimal OpenID Provider for local trials and tests
  gen-cert.sh  self-signed localhost certificate
test/        node:test — unit tests plus end-to-end flows against the mock
```

## Tests

```sh
npm test
```

Covers the full authorization-code flow against the mock provider (client secret
post/basic, `private_key_jwt` with the public JWKS hosted on a separate link, PEM
keys, encrypted ID token + UserInfo, signed-JWT UserInfo, `access_denied`, tampered
`state`, wrong secret) and request validation.

## Notes

- The mock provider supports `private_key_jwt` too: start it with
  `MOCK_OP_CLIENT_JWKS_URI=<url of your hosted JWKS> npm run mock-op`; add
  `MOCK_OP_ENCRYPT_ID_TOKEN=1` / `MOCK_OP_ENCRYPT_USERINFO=1` to get encrypted
  responses, `MOCK_OP_USERINFO_JWT=1` for a signed-JWT UserInfo.
- `prompt=none` against the mock always yields `login_required` (it has no session
  to reuse) — handy for checking the error path.
- Standard claims and scopes follow [OpenID Connect Core 1.0 §5](https://openid.net/specs/openid-connect-core-1_0.html#Claims);
  itsme claims follow the [itsme developer documentation](https://belgianmobileid.github.io/doc/IAM).
