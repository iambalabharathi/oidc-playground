# OIDC Playground

A static, stateless page for trying OpenID Connect requests — made to be hosted
on GitHub Pages. Fill in the provider and your client, pick the scopes and claims
you want, authorize at the provider, come back and inspect everything it says:
the token response, the ID token (claims, decoded JWT, raw JWT, validation
checks) and the UserInfo response as plain values.

Built for testing itsme® (sandbox or production), works with any provider that
publishes a discovery document.

```
page  ── builds the request (state, nonce, PKCE) ──▶ <issuer>/authorization
page  ◀── provider redirects back to the page with ?code=…&state=… ──
page  ── token endpoint (code + client credentials) ──▶ provider      ← in the browser (oauth4webapi)
page  ◀── tokens; ID token validated: signature, iss, aud, exp, nonce, at_hash
page  ── userinfo endpoint (access token) ──▶ provider ──▶ plain values
```

**Nothing is configured or stored anywhere but your browser.** Issuer, client id,
service code, scopes and claims are remembered in `localStorage`; the client
secret or private key only in `sessionStorage` (this tab, until you close it).
The JWKS with your **public** key lives wherever you host it (the `jwks_uri`
registered at the provider) — the page only needs the private key, pasted, to
sign the `private_key_jwt` assertion and to decrypt encrypted responses.

## Hosting on GitHub Pages

The site is the `docs/` folder — plain HTML/CSS/JS, no build step.

1. Repository → **Settings → Pages** → *Deploy from a branch* → branch `main`,
   folder `/docs`.
2. The page is then at `https://<user>.github.io/oidc-playground/` — that exact
   URL is the **redirect URI** to register at the provider (the page shows it).

Two third-party libraries are vendored in `docs/vendor/` (ESM, loaded by the
browser): [oauth4webapi](https://github.com/panva/oauth4webapi) for the protocol
and [jose](https://github.com/panva/jose) for keys / JWE. Refresh them with
`npm run vendor`.

### The CORS caveat

Everything runs in the browser, so the provider's discovery document, token
endpoint and userinfo endpoint must allow cross-origin requests from the page's
origin. Many providers do not (they are built for server-side clients). For those,
switch **Exchange the code through** to *local helper* and run

```sh
npm install
npm start          # http://localhost:3000 — serves the page too
```

The helper is a small stateless Node service (`server/`): the page sends it the
callback URL plus your client details, it talks to the provider and returns the
result. It keeps nothing. Browsers allow a page on https to call `http://localhost`,
so the GitHub Pages version works with a helper running on your machine.

## Quick start without credentials

```sh
npm install
npm run mock-op    # terminal 1: a tiny OpenID Provider on http://localhost:9000 (CORS enabled)
npm start          # terminal 2: the page on http://localhost:3000
```

Preset **Local mock provider**, client id `playground`, `client_secret_post` with
secret `secret`, **Authorize**, approve on the mock consent page. The mock persona
is *Lotte Vermeulen*; it deliberately never returns `gender`, so you can see how a
requested-but-missing claim is shown.

## Against itsme®

1. Register the page URL as redirect URI for your client (GitHub Pages URL, or
   `https://localhost:8443/` when running the helper with TLS — itsme only accepts
   https; see `npm run cert` and `.env.example`).
2. In the page: preset **itsme® sandbox**, your client id and service code, and
   either the client secret (`client_secret_post`) or your private key
   (`private_key_jwt`) pasted as JWK or PEM. The page shows the key's kid, alg
   and public JWK — compare them with the JWKS you host on your public link.
3. If itsme's endpoints refuse cross-origin requests from the page (you will see a
   *network_error* at discovery or at the token step), use the local helper.
4. Encrypted ID tokens / UserInfo (JWE) are decrypted automatically with the pasted
   RSA private key, whatever the authentication method.

## What the page does

**1 · Build request** — provider (presets or any issuer) with live discovery,
client id, client authentication (`client_secret_post`, `client_secret_basic`,
`private_key_jwt`, `none`), the redirect URI to register; scopes as toggles
(`openid` fixed, `service:<code>` for itsme, `profile`, `email`, `phone`, `address`,
`eid`, `offline_access`); every standard claim from OpenID Connect Core §5.1 plus
the itsme® claims (requested by their full `http://itsme.services/v2/claim/…` URI),
an *essential* flag per claim, delivery in UserInfo, the ID token, or both (the
`claims` request parameter). Request options: `acr_values` (presets plus what
discovery advertises), `prompt`, `ui_locales`, `max_age`, `login_hint`, PKCE on/off.

**2 · Authorize** — `state`, `nonce` and the PKCE verifier are generated in the
browser, remembered in the tab, and you are redirected to the provider.

**3 · Tokens & claims** — back on the page the one-time code is taken from the URL
(and removed from the address bar), `state` is verified, the code is exchanged and
the ID token validated: signature against `jwks_uri`, `iss`, `aud`, `exp`, `iat`,
`nonce`, `auth_time`/`max_age`, `at_hash`. You see the token response (copyable
tokens), the ID token as *Claims* (about the user and about itself, requested-but-
missing claims marked), *Decoded* and *Raw JWT*, the list of checks, and the exact
request that was sent.

**4 · UserInfo** — one click calls the userinfo endpoint with the access token and
shows the plain values, the raw response, a "requested vs returned" summary and
whether the values match the ID token. JSON, signed JWT and encrypted JWT
responses are all handled.

## Project layout

```
docs/          the page (GitHub Pages root)
  index.html, css/styles.css
  js/app.js          request builder, return from the provider, result page
  js/oidc-client.js  discovery, code exchange, ID token checks, userinfo, keys (oauth4webapi + jose)
  js/backends.js     "direct" (browser) and "helper" (local Node) with the same interface
  js/catalog.js      presets, scopes, standard + itsme claims, request builders
  vendor/            oauth4webapi.js, jose.js (vendored ESM)
server/        optional local helper — stateless JSON API + static hosting of docs/
tools/
  mock-op.js   minimal OpenID Provider for local trials and tests (CORS, PKCE, private_key_jwt, JWE)
  gen-cert.sh  self-signed localhost certificate for the helper
test/          node:test — the browser client and the helper API, both against the mock
```

## Helper API (only when you use the helper)

| route | body | returns |
| --- | --- | --- |
| `POST /api/discover` | `{ issuer }` | endpoints and capabilities |
| `POST /api/token` | `{ issuer, client_id, client_auth: { method, client_secret?, private_key? }, callback_url, expected_state, expected_nonce, code_verifier?, max_age? }` | `tokens`, `idToken { header, payload, checks }` |
| `POST /api/userinfo` | `{ issuer, client_id, access_token, expected_sub, private_key? }` | request/response details, `claims`, `checks` |
| `POST /api/keys/inspect` | `{ private_key }` | `kid`, `alg`, `public_jwk` |

Every response is `{ ok: true, … }` or `{ ok: false, error: { error, error_description, stage } }`.
`http://` issuers are accepted for localhost only (`ALLOW_INSECURE_ISSUER=1` to override).
Helper settings (`PORT`, `TLS_KEY_FILE`, `TLS_CERT_FILE`, `TRUST_PROXY`, `DISCOVERY_CACHE_SECONDS`)
are documented in `.env.example`.

## Tests

```sh
npm test
```

Runs the browser client (in Node) and the helper API against the mock provider:
client secret post/basic, `private_key_jwt` with the public JWKS on a separate link,
PEM keys, encrypted ID token + UserInfo, signed-JWT UserInfo, `access_denied`,
tampered `state`, wrong secret, request validation.

## Notes

- Mock provider options: `MOCK_OP_CLIENT_JWKS_URI=<url of your hosted JWKS>` enables
  `private_key_jwt`; `MOCK_OP_ENCRYPT_ID_TOKEN=1` / `MOCK_OP_ENCRYPT_USERINFO=1` give
  encrypted responses; `MOCK_OP_USERINFO_JWT=1` a signed-JWT UserInfo.
- `prompt=none` against the mock always yields `login_required` — handy for the error path.
- Standard claims and scopes follow [OpenID Connect Core 1.0 §5](https://openid.net/specs/openid-connect-core-1_0.html#Claims);
  itsme claims follow the [itsme developer documentation](https://belgianmobileid.github.io/doc/IAM).
