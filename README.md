# OIDC Playground

A static page for building OpenID Connect authorization requests by hand, made to
be hosted on GitHub Pages. Fill in the provider and your client, pick the scopes
and claims, set the request options, add any other parameter you need, and open
the exact URL the page shows. No server, key or secret is involved.

Works with any OpenID Provider that publishes a discovery document.

```
page  ── builds the request (state, nonce, PKCE) ──▶ <issuer>/authorization   (opens in a new tab)
your redirect URI  ◀── provider redirects with ?code=…&state=… ──
```

The page shows the `state`, `nonce` and PKCE `code_verifier` of the request, so
whatever redeems the code at your redirect URI can be given them.

Optionally the page can also redeem the code itself and show the tokens, the ID
token and UserInfo: see [Code exchange](#code-exchange-optional).

**Nothing is configured or stored anywhere but your browser.** The form is
remembered in `localStorage`. A client secret or private key, used only when code
exchange is on, stays in `sessionStorage` (this tab, until you close it).

## Hosting on GitHub Pages

The site is the `docs/` folder: plain HTML/CSS/JS, no build step.

1. Push the repository to GitHub.
2. Repository → **Settings → Pages** → *Deploy from a branch* → branch `main`,
   folder `/docs`.
3. The page is then at `https://<user>.github.io/<repo>/`.

Discovery is fetched by the browser, so the provider's discovery document must
allow cross-origin requests. Most do.

## Building a request

1. **Provider & client**: the issuer URL (discovery loads the endpoints), your
   client id, and the redirect URI your client is registered with. Left alone, the
   redirect URI is the page itself.
2. **Scopes**: `openid` is fixed; provider-specific scopes go in *Additional scopes*.
3. **Claims**: every standard claim from OpenID Connect Core §5.1 plus custom
   claims (any name or URI), an *essential* flag per claim, delivery in UserInfo,
   the ID token, or both. They are sent as the `claims` request parameter.
4. **Request options**: `acr_values`, `prompt`, `ui_locales`, `max_age`,
   `login_hint`, PKCE on/off, and **Extra parameters**: one `key=value` per line,
   added to the URL as typed. A name that already exists (`response_type`, `state`,
   `nonce`, …) replaces that value.
5. **Authorization request**: the exact URL, its `state`, `nonce` and
   `code_verifier`, a copy button and a button that opens it in a new tab. The
   values stay the same until you press *New values* or reload the page.

When PKCE is on, whoever redeems the code needs the `code_verifier`. Turn PKCE off
if the server at your redirect URI cannot send it.

If the redirect URI is the page itself, the page shows the callback parameters it
received and whether `state` matches the request it opened.

## Code exchange (optional)

Under **Code exchange** the page can redeem the code and validate the result:

- **in this browser**: the token and userinfo endpoints are called from the page
  (oauth4webapi). The provider must allow cross-origin requests on them; many do
  not, and you then see a *network_error* at the token step.
- **through a helper**: a server that makes the same calls for the page. The
  repository contains one (`server/`, a small stateless Node service):

  ```sh
  npm install
  npm start          # http://localhost:3000, serves the page too
  ```

With code exchange on, the section also asks for the client authentication
(`private_key_jwt`, `client_secret_post`, `client_secret_basic`, `none`):

- For `private_key_jwt`, the **Private key URL** serves your private key as a JWK,
  a JWKS with your private keys (a `use: sig` key for the client assertion and,
  optionally, a `use: enc` RSA key for encrypted responses) or PEM. The browser
  fetches it, so the host must allow cross-origin requests; otherwise paste the
  key. The page shows the kid, alg and public JWK of the signing key.
- **Assertion audience** sets the `aud` of the signed assertion: the token
  endpoint URL (OpenID Connect Core §9, the default) or the issuer identifier.
  A wrong one typically shows up as `unauthorized_client` or `invalid_client`.
- Encrypted ID tokens / UserInfo (JWE) are decrypted with the RSA private key.

The request then starts in the same tab. If the redirect URI is the page, the
provider comes straight back and the exchange runs. If it is another registered
URI, paste the complete URL you land on into **Finish the request** at the top of
the page, in the tab that started the request.

The result shows the token response, the ID token as *Claims*, *Decoded* and *Raw
JWT*, the validation checks (signature against `jwks_uri`, `iss`, `aud`, `exp`,
`iat`, `nonce`, `auth_time`/`max_age`, `at_hash`), the request that was sent, and
one click calls UserInfo and compares its values with the ID token.

Two third-party libraries are vendored in `docs/vendor/` (ESM, loaded by the
browser): [oauth4webapi](https://github.com/panva/oauth4webapi) for the protocol
and [jose](https://github.com/panva/jose) for keys / JWE. Refresh them with
`npm run vendor`.

## Project layout

```
docs/          the page (GitHub Pages root)
  index.html, css/styles.css
  js/app.js          request builder, return from the provider, result page
  js/oidc-client.js  discovery, code exchange, ID token checks, userinfo, keys (oauth4webapi + jose)
  js/backends.js     code exchange "direct" (browser) and "helper" (a server) with the same interface
  js/catalog.js      scopes, standard + custom claims, request builders
  vendor/            oauth4webapi.js, jose.js (vendored ESM)
server/        optional helper for code exchange — stateless JSON API + static hosting of docs/
tools/
  gen-cert.sh  self-signed localhost certificate for the helper
test/          node:test — the claim catalog / request builders and the key parsing
```

## Helper API (only when you use the helper)

| route | body | returns |
| --- | --- | --- |
| `POST /api/discover` | `{ issuer }` | endpoints and capabilities |
| `POST /api/token` | `{ issuer, client_id, client_auth: { method, client_secret?, private_key? }, callback_url, expected_state, expected_nonce, code_verifier?, max_age? }` | `tokens`, `idToken { header, payload, checks }` (`private_key`: JWK, private JWKS or PEM) |
| `POST /api/userinfo` | `{ issuer, client_id, access_token, expected_sub, private_key? }` | request/response details, `claims`, `checks` |
| `POST /api/keys/inspect` | `{ private_key }` | `kid`, `alg`, `public_jwk`, `decryption_kids`, `keys_found` |

Every response is `{ ok: true, … }` or `{ ok: false, error: { error, error_description, stage } }`.
`http://` issuers are accepted for localhost only (`ALLOW_INSECURE_ISSUER=1` to override).
Helper settings (`PORT`, `TLS_KEY_FILE`, `TLS_CERT_FILE`, `TRUST_PROXY`, `DISCOVERY_CACHE_SECONDS`)
are documented in `.env.example`.

## Tests

```sh
npm test
```

Pure unit tests: the request builders (scopes, the `claims` parameter, the
authorization parameters) and the private key parsing shared by the browser client
and the helper (JWK, private JWKS with `sig` + `enc` keys, PEM, public-only JWKS).
There is no test provider in the repository; try the flow against your own.

## Notes

- `http://` issuers are accepted by the helper for localhost only (`ALLOW_INSECURE_ISSUER=1` to override).
- Standard claims and scopes follow [OpenID Connect Core 1.0 §5](https://openid.net/specs/openid-connect-core-1_0.html#Claims).
