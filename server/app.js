// HTTP layer: a stateless JSON API for the page plus static hosting.
// The server never stores tokens, secrets or flow state — the page sends what
// each call needs, gets the result back, and keeps it in the browser.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { validateDiscoverRequest, validateTokenRequest, validateUserinfoRequest, validateInspectKeyRequest, ValidationError } from './validate.js';
import { describeError } from './oidc.js';

const publicDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../public');

export function createApp({ settings, oidc, log = console }) {
  const app = express();
  app.disable('x-powered-by');
  if (settings.trustProxy) app.set('trust proxy', 1);
  app.use(express.json({ limit: '256kb' }));
  app.use('/api', (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
  });

  const handle = (validate, run, stage) => async (req, res) => {
    let input;
    try {
      input = validate(req.body);
    } catch (err) {
      if (err instanceof ValidationError) return res.status(400).json({ ok: false, error: { error: 'invalid_request', error_description: err.message, errors: err.errors, stage } });
      throw err;
    }
    try {
      const result = await run(input);
      res.json({ ok: true, ...result });
    } catch (err) {
      const described = describeError(err, stage);
      log.warn(`[${stage}] ${described.error}: ${described.error_description}`);
      res.json({ ok: false, error: described });
    }
  };

  // Discovery document of the issuer typed in the page.
  app.post('/api/discover', handle(validateDiscoverRequest, async ({ issuer }) => ({ provider: await oidc.describeProvider(issuer) }), 'discovery'));

  // The provider redirected the browser to /callback?code=…&state=…; the page sends that URL
  // together with the client details and what it remembered (state, nonce, code_verifier).
  app.post('/api/token', handle(validateTokenRequest, (input) => oidc.exchangeCode(input), 'token'));

  // UserInfo with the access token the page got back from /api/token.
  app.post('/api/userinfo', handle(validateUserinfoRequest, async (input) => ({ userinfo: await oidc.fetchUserinfo(input) }), 'userinfo'));

  // Shows kid / alg / public JWK of a pasted private key so it can be compared with the hosted JWKS.
  app.post('/api/keys/inspect', handle(validateInspectKeyRequest, async ({ privateKey }) => ({ key: await oidc.inspectKey(privateKey) }), 'key'));

  app.use((req, res, next) => {
    if (req.path.startsWith('/api/')) return res.status(404).json({ ok: false, error: { error: 'not_found', error_description: `No API route ${req.method} ${req.path}` } });
    next();
  });

  // --- Frontend --------------------------------------------------------------
  app.use(express.static(publicDir, { index: false, maxAge: 0 }));
  app.use((req, res, next) => {
    // Client-side routes (/, /callback, /result) get the page; anything that looks like a file 404s.
    if (req.method !== 'GET' || path.extname(req.path)) return next();
    res.sendFile(path.join(publicDir, 'index.html'));
  });

  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    if (err?.type === 'entity.parse.failed' || err?.type === 'entity.too.large') {
      return res.status(400).json({ ok: false, error: { error: 'invalid_request', error_description: err.message } });
    }
    log.error('[http]', err);
    res.status(500).json({ ok: false, error: { error: 'internal_error', error_description: err.message } });
  });

  return app;
}
