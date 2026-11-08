# OIDC Playground

Pick the scopes and claims you want, send a real OpenID Connect authentication
request to the provider, come back with the code, and inspect everything the
provider says: the token response, the ID token (claims, decoded JWT, raw JWT,
validation checks) and the UserInfo response as plain values.

Built for testing itsme® (sandbox or production), but it works with any
OpenID Connect provider that publishes a discovery document.

```
browser ──▶ this app (/api/auth/start) ──▶ redirect to <issuer>/authorization
browser ◀── provider ──▶ this app (/callback): code → token endpoint → ID token validated
browser ──▶ /result shows tokens & claims ──▶ /api/userinfo calls the userinfo endpoint
```

Tokens never reach the browser: the backend keeps them in a server-side session
and the page only shows what `/api/result` returns.

## Quick start (no credentials needed)

```sh
npm install
npm run mock-op        # terminal 1: a tiny OpenID Provider on http://localhost:9000
npm run start:mock     # terminal 2: the playground on http://localhost:3000, pointed at the mock
```

Open http://localhost:3000, pick claims, press **Authorize**, approve on the mock
consent page and you land on the result page. The mock persona is *Lotte
Vermeulen*; it deliberately never returns `gender`, so you can see how a
requested-but-missing claim is shown.

## Against itsme®

1. `cp .env.example .env` and fill in `CLIENT_ID`, your `SERVICE_CODE` and either
   `CLIENT_SECRET` (client_secret_post) or `PRIVATE_KEY_FILE` (private_key_jwt,
   a JWK or PEM private key).
2. itsme only accepts **https** redirect URIs: run `npm run cert` once (self-signed
   certificate for `https://localhost:8443`) and keep the `TLS_*` lines in `.env`.
3. Register `https://localhost:8443/callback` as a redirect URI for your client at
   itsme. With `private_key_jwt`, also register `https://localhost:8443/.well-known/jwks.json`
   as your `jwks_uri` (or paste the JWKS it serves) — that URL must be reachable by
   itsme, so for the sandbox you will usually expose the app through a tunnel
   (e.g. `ngrok http 8443`, then set `BASE_URL` to the tunnel URL and `TRUST_PROXY=1`).
4. `npm start` and open the `BASE_URL`.

If your itsme client is configured to receive **encrypted** ID tokens / UserInfo,
set `DECRYPT_RESPONSES=1` (needs an RSA `PRIVATE_KEY_FILE`); the page then shows
the JWE header, the decrypted claims and the nested signature check.

## What the page does

**1 · Build request** — scopes as toggles (`openid` fixed, `service:<code>` for
itsme, `profile`, `email`, `phone`, `address`, `eid`, `offline_access`), every
standard claim from OpenID Connect Core §5.1 plus the itsme® claims (requested by
their full `http://itsme.services/v2/claim/…` URI), an *essential* flag per claim,
and a choice of delivering them in UserInfo, the ID token, or both — this becomes
the `claims` request parameter. Request options: `acr_values`, `prompt`,
`ui_locales`, `max_age`, `login_hint`, PKCE on/off. The authorization request and
the `claims` JSON are previewed live; `state`, `nonce` and the PKCE verifier are
generated server-side when you click **Authorize**.

**2 · Authorize** — you are redirected to the provider and come back to `/callback`.
The backend verifies `state`, exchanges the code (with `code_verifier`), and
validates the ID token with [openid-client](https://github.com/panva/openid-client):
signature against `jwks_uri`, `iss`, `aud`, `exp`, `iat`, `nonce`, `auth_time`/`max_age`;
`at_hash` is checked additionally.

**3 · Tokens & claims** — token response (copyable tokens), the ID token as
*Claims* (what it says about the user and about itself, with requested-but-missing
claims marked), *Decoded* (header / payload / signature) and *Raw JWT*, plus the
list of validation checks. The exact request that was sent is kept as well.

**4 · UserInfo** — one click calls the userinfo endpoint with the access token and
shows the plain values, the raw response, a "requested vs returned" summary, and
whether the values match the ID token. JSON, signed JWT and encrypted JWT
responses are all handled.

## Configuration

| variable | meaning |
| --- | --- |
| `ISSUER` | Issuer identifier; discovery at `<ISSUER>/.well-known/openid-configuration` |
| `CLIENT_ID` | Your client id |
| `CLIENT_AUTH` | `client_secret_post`, `client_secret_basic`, `private_key_jwt` or `none`; inferred when empty |
| `CLIENT_SECRET` | For the `client_secret_*` methods |
| `PRIVATE_KEY_FILE` / `PRIVATE_KEY_JWK` | Private key (JWK JSON or PEM) for `private_key_jwt` and for decrypting JWE |
| `DECRYPT_RESPONSES` | `1` when the provider encrypts the ID token / UserInfo for your client |
| `SERVICE_CODE` | Default itsme service code → `service:<code>` scope |
| `BASE_URL`, `PORT` | Where this app runs; `REDIRECT_URI` defaults to `<BASE_URL>/callback` |
| `TLS_KEY_FILE`, `TLS_CERT_FILE` | Serve https (see `npm run cert`) |
| `SESSION_SECRET` | Cookie signing secret |
| `TRUST_PROXY` | `1` behind a tunnel / reverse proxy |
| `ALLOW_INSECURE_ISSUER` | Allow an `http://` issuer (automatic for the mock) |

## Project layout

```
server/      Express backend (relying party)
  index.js     start-up, http/https
  app.js       routes: /api/config, /api/auth/start, /callback, /api/result, /api/userinfo, /api/reset, /.well-known/jwks.json
  oidc.js      discovery, authorization URL, code exchange, ID token checks, userinfo (openid-client + jose)
  jwt.js       decoding helpers, at_hash, JWT/JWE userinfo parsing
  keys.js      RP private key → signing key, decryption keys, public JWKS
  validate.js  validation of what the page sends
  config.js    environment → settings
public/      the page (no build step)
  js/catalog.js  scopes, standard + itsme claims, request builder (shared with tests)
  js/app.js      request builder and result page
tools/
  mock-op.js   minimal OpenID Provider for local trials and tests
  gen-cert.sh  self-signed localhost certificate
test/        node:test — unit tests for the catalog/validation and an end-to-end flow against the mock
```

## Tests

```sh
npm test
```

Runs the unit tests and a full authorization-code flow (including a signed-JWT
UserInfo response, an `access_denied` callback, a tampered `state`, and request
validation) against the mock provider on random ports.

## Notes

- The session store is in-memory: restarting the server forgets tokens, which is
  what you want for a test tool.
- `prompt=none` against the mock always yields `login_required` (it has no session
  to reuse) — handy for checking the error path.
- Standard claims and scopes follow [OpenID Connect Core 1.0 §5](https://openid.net/specs/openid-connect-core-1_0.html#Claims);
  itsme claims follow the [itsme developer documentation](https://belgianmobileid.github.io/doc/IAM).
