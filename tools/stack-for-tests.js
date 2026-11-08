// Test support: boots the mock provider and the playground on random ports,
// hosts a JWKS "somewhere public", and builds authorization URLs the way the page does.
import http from 'node:http';
import { createHash, randomBytes } from 'node:crypto';
import { loadSettings } from '../server/config.js';
import { createOidc } from '../server/oidc.js';
import { createApp } from '../server/app.js';
import { startMockOp } from './mock-op.js';

const quietLog = { log() {}, warn() {}, error() {} };

export async function bootStack({ mockOptions = {}, env = {} } = {}) {
  const op = await startMockOp({ port: 0, autoApprove: true, quiet: true, ...mockOptions });
  const settings = loadSettings({ PORT: '3999', ...env });
  const oidc = createOidc(settings, quietLog);
  const app = createApp({ settings, oidc, log: quietLog });
  const server = await new Promise((resolve) => {
    const s = http.createServer(app).listen(0, '127.0.0.1', () => resolve(s));
  });
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  return {
    op,
    settings,
    baseUrl,
    redirectUri: `${baseUrl}/callback`,
    async close() {
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
      await op.close();
    },
  };
}

/** Plain JSON client for the API (no cookies — the server is stateless). */
export function makeApi(baseUrl) {
  const call = async (path, init = {}) => fetch(baseUrl + path, { ...init, redirect: 'manual' });
  return {
    call,
    get: async (path) => (await call(path)).json(),
    post: async (path, body) => {
      const res = await call(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body ?? {}) });
      const text = await res.text();
      let json;
      try {
        json = JSON.parse(text);
      } catch {
        json = { ok: false, raw: text };
      }
      return { status: res.status, ...json };
    },
  };
}

/** Serves a JWKS document on a loopback port, like a JWKS hosted on a public link would be. */
export async function hostJwks(jwks) {
  const server = await new Promise((resolve) => {
    const s = http
      .createServer((req, res) => {
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify(jwks));
      })
      .listen(0, '127.0.0.1', () => resolve(s));
  });
  return {
    url: `http://127.0.0.1:${server.address().port}/jwks.json`,
    close: () => {
      server.closeAllConnections();
      return new Promise((resolve) => server.close(resolve));
    },
  };
}

/** What the page does in the browser before redirecting: random state/nonce, PKCE, the URL. */
export function startFlow({ authorizationEndpoint, clientId, redirectUri, scopes = ['openid'], claims = null, pkce = true, extra = {} }) {
  const state = randomBytes(24).toString('base64url');
  const nonce = randomBytes(24).toString('base64url');
  const codeVerifier = pkce ? randomBytes(48).toString('base64url') : null;
  const url = new URL(authorizationEndpoint);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('scope', scopes.join(' '));
  url.searchParams.set('state', state);
  url.searchParams.set('nonce', nonce);
  if (codeVerifier) {
    url.searchParams.set('code_challenge', createHash('sha256').update(codeVerifier).digest('base64url'));
    url.searchParams.set('code_challenge_method', 'S256');
  }
  for (const [k, v] of Object.entries(extra)) url.searchParams.set(k, String(v));
  if (claims) url.searchParams.set('claims', JSON.stringify(claims));
  return { url: url.href, state, nonce, codeVerifier };
}

/** Follows the redirect to the (auto-approving) mock and returns the callback URL it sends the browser to. */
export async function authorizeAtMock(flow) {
  const res = await fetch(flow.url, { redirect: 'manual' });
  if (res.status !== 302) throw new Error(`expected a redirect from the mock, got ${res.status}: ${await res.text()}`);
  return res.headers.get('location');
}
