// Two interchangeable ways to do the parts a static page cannot do alone:
//  - direct: in this browser, with oauth4webapi (needs CORS on the provider's endpoints)
//  - helper: through the optional local Node helper (server/), for providers without CORS
// Both expose the same four calls and the same { ok, ... } / { ok: false, error } shapes.
import { discover, exchangeCode, fetchUserinfo, inspectKey, describeError } from './oidc-client.js';

const asCache = new Map(); // issuer → { as, at }
const AS_TTL_MS = 5 * 60 * 1000;

async function authorizationServer(issuer) {
  const key = issuer.replace(/\/+$/, '');
  const cached = asCache.get(key);
  if (cached && Date.now() - cached.at < AS_TTL_MS) return cached.as;
  const { as } = await discover(key);
  asCache.set(key, { as, at: Date.now() });
  return as;
}

export const direct = {
  id: 'direct',
  async discover(issuer) {
    try {
      const { as, provider } = await discover(issuer);
      asCache.set(issuer.replace(/\/+$/, ''), { as, at: Date.now() });
      return { ok: true, provider };
    } catch (err) {
      return { ok: false, error: describeError(err, 'discovery') };
    }
  },
  async token(body) {
    try {
      const as = await authorizationServer(body.issuer);
      const result = await exchangeCode({
        as,
        clientId: body.client_id,
        auth: { method: body.client_auth.method, clientSecret: body.client_auth.client_secret, privateKeyMaterial: body.client_auth.private_key },
        callbackUrl: body.callback_url,
        redirectUri: body.redirect_uri,
        expectedState: body.expected_state,
        expectedNonce: body.expected_nonce,
        codeVerifier: body.code_verifier,
        maxAge: body.max_age,
      });
      return { ok: true, ...result };
    } catch (err) {
      return { ok: false, error: describeError(err, 'token') };
    }
  },
  async userinfo(body) {
    try {
      const as = await authorizationServer(body.issuer);
      const userinfo = await fetchUserinfo({ as, clientId: body.client_id, accessToken: body.access_token, expectedSub: body.expected_sub, privateKeyMaterial: body.private_key });
      return { ok: true, userinfo };
    } catch (err) {
      return { ok: false, error: describeError(err, 'userinfo') };
    }
  },
  async inspectKey(material) {
    try {
      return { ok: true, key: await inspectKey(material) };
    } catch (err) {
      return { ok: false, error: describeError(err, 'key') };
    }
  },
};

export function helper(baseUrl) {
  const base = String(baseUrl || '').replace(/\/+$/, '');
  async function post(path, body) {
    let response;
    try {
      response = await fetch(base + path, {
        method: 'POST',
        headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
        body: JSON.stringify(body ?? {}),
      });
    } catch (err) {
      return { ok: false, error: { error: 'helper_unreachable', error_description: `Cannot reach the helper at ${base} (${err.message}). Start it with "npm start" and check the URL.` } };
    }
    const text = await response.text();
    try {
      const json = JSON.parse(text);
      if (json && typeof json === 'object' && 'ok' in json) return json;
      return { ok: false, error: { error: 'bad_response', error_description: text.slice(0, 300) } };
    } catch {
      return { ok: false, error: { error: 'bad_response', error_description: `HTTP ${response.status}: ${text.slice(0, 300)}` } };
    }
  }
  return {
    id: 'helper',
    discover: (issuer) => post('/api/discover', { issuer }),
    token: (body) => post('/api/token', body),
    userinfo: (body) => post('/api/userinfo', body),
    inspectKey: (privateKey) => post('/api/keys/inspect', { private_key: privateKey }),
  };
}

export function backendFor(form) {
  return form.mode === 'helper' ? helper(form.helperUrl) : direct;
}
