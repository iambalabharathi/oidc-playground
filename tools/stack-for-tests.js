import http from 'node:http';
import { loadSettings } from '../server/config.js';
import { loadRpKeys } from '../server/keys.js';
import { createOidc } from '../server/oidc.js';
import { createApp } from '../server/app.js';
import { startMockOp } from './mock-op.js';

const quietLog = { log() {}, warn() {}, error() {} };

/** Boots a mock provider and the playground against it on random ports. */
export async function bootStack({ mockOptions = {}, env = {} } = {}) {
  const op = await startMockOp({ port: 0, autoApprove: true, quiet: true, ...mockOptions });

  const settings = loadSettings({
    ISSUER: op.issuer,
    CLIENT_ID: op.clientId,
    CLIENT_SECRET: op.clientSecret,
    CLIENT_AUTH: 'client_secret_post',
    BASE_URL: 'http://127.0.0.1:3999',
    PORT: '3999',
    SESSION_SECRET: 'test-secret',
    SERVICE_CODE: 'TESTSERVICE',
    ...env,
  });
  const rpKeys = await loadRpKeys(settings);
  const oidc = createOidc(settings, rpKeys, quietLog);
  const app = createApp({ settings, oidc, rpKeys, log: quietLog });

  const server = await new Promise((resolve) => {
    const s = http.createServer(app).listen(0, '127.0.0.1', () => resolve(s));
  });
  settings.baseUrl = `http://127.0.0.1:${server.address().port}`;
  settings.redirectUri = `${settings.baseUrl}/callback`;

  return {
    op,
    settings,
    baseUrl: settings.baseUrl,
    async close() {
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
      await op.close();
    },
  };
}

/** Minimal cookie-jar fetch for one browser session. */
export function makeSession(baseUrl) {
  let cookie = null;
  async function call(path, init = {}) {
    const url = path.startsWith('http') ? path : baseUrl + path;
    const headers = { ...(init.headers || {}) };
    if (cookie) headers.cookie = cookie;
    const res = await fetch(url, { ...init, headers, redirect: 'manual' });
    const setCookie = res.headers.get('set-cookie');
    if (setCookie) cookie = setCookie.split(';')[0];
    return res;
  }
  return {
    call,
    json: async (path, init) => (await call(path, init)).json(),
    post: (path, body) =>
      call(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body ?? {}) }),
  };
}
