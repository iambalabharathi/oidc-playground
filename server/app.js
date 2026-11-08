// HTTP layer: a few JSON endpoints for the page, the /callback the provider
// redirects to, and static hosting of the frontend. Tokens stay in the
// server-side session; the browser only ever sees what the API returns.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import session from 'express-session';
import { validateStartRequest, ValidationError } from './validate.js';
import { describeError } from './oidc.js';

const publicDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../public');

export function createApp({ settings, oidc, rpKeys, log = console }) {
  const app = express();
  app.disable('x-powered-by');
  if (settings.trustProxy) app.set('trust proxy', 1);

  app.use(express.json({ limit: '64kb' }));
  app.use(
    session({
      name: 'oidc_playground.sid',
      secret: settings.sessionSecret,
      resave: false,
      saveUninitialized: false,
      cookie: {
        httpOnly: true,
        sameSite: 'lax',
        secure: settings.baseUrl.startsWith('https://'),
        maxAge: 2 * 60 * 60 * 1000,
      },
    }),
  );

  // --- API -----------------------------------------------------------------

  app.get('/api/config', async (req, res) => {
    const discovery = await oidc.describeProvider();
    res.json({
      provider: {
        label: settings.providerLabel,
        issuer: settings.issuer,
        clientId: settings.clientId,
        redirectUri: settings.redirectUri,
        clientAuth: settings.clientAuth,
        serviceCode: settings.serviceCode,
        decryptResponses: settings.decryptResponses,
        jwksUrl: rpKeys ? `${settings.baseUrl}/.well-known/jwks.json` : null,
      },
      discovery,
    });
  });

  app.post('/api/auth/start', async (req, res, next) => {
    try {
      const selection = validateStartRequest(req.body);
      const { url, params, pending } = await oidc.startAuthorization(selection);
      req.session.pending = {
        ...pending,
        request: { url, params, selection, startedAt: pending.startedAt },
      };
      delete req.session.result;
      req.session.save((err) => {
        if (err) return next(err);
        res.json({ url, params });
      });
    } catch (err) {
      if (err instanceof ValidationError) {
        return res.status(400).json({ error: 'invalid_request', errors: err.errors });
      }
      log.error('[start]', err);
      res.status(502).json({ error: 'start_failed', detail: describeError(err, 'start') });
    }
  });

  app.get('/callback', async (req, res, next) => {
    const pending = req.session.pending;
    const callbackUrl = new URL(req.originalUrl, settings.baseUrl);
    const query = Object.fromEntries(callbackUrl.searchParams);
    const callback = {
      url: `${callbackUrl.pathname}${callbackUrl.search}`,
      query,
      receivedAt: new Date().toISOString(),
    };

    if (!pending) {
      req.session.result = {
        status: 'error',
        callback,
        error: {
          stage: 'callback',
          error: 'no_pending_request',
          error_description:
            'The callback arrived without a matching request in this browser session (expired, already used, or started elsewhere). Start a new request.',
        },
      };
      return req.session.save(() => res.redirect('/result'));
    }

    delete req.session.pending;
    try {
      const outcome = await oidc.completeAuthorization(callbackUrl, pending);
      req.session.result = {
        status: 'ok',
        request: pending.request,
        callback,
        tokens: { ...outcome.tokens, receivedAt: new Date().toISOString() },
        idToken: outcome.idToken,
        userinfo: null,
      };
    } catch (err) {
      log.warn('[callback]', err.message);
      req.session.result = {
        status: 'error',
        request: pending.request,
        callback,
        error: describeError(err, 'token'),
      };
    }
    req.session.save((err) => {
      if (err) return next(err);
      res.redirect('/result');
    });
  });

  app.get('/api/result', (req, res) => {
    res.json(req.session.result || { status: 'empty' });
  });

  app.post('/api/userinfo', async (req, res, next) => {
    const result = req.session.result;
    if (!result || result.status !== 'ok') {
      return res.status(409).json({ error: 'no_tokens', error_description: 'Complete an authorization first.' });
    }
    try {
      const userinfo = await oidc.fetchUserinfo(result.tokens.access_token, result.idToken.payload.sub);
      result.userinfo = userinfo;
      req.session.save((err) => {
        if (err) return next(err);
        res.json(userinfo);
      });
    } catch (err) {
      log.warn('[userinfo]', err.message);
      res.status(502).json({ error: 'userinfo_failed', detail: describeError(err, 'userinfo') });
    }
  });

  app.post('/api/reset', (req, res) => {
    req.session.destroy(() => {
      res.clearCookie('oidc_playground.sid');
      res.json({ ok: true });
    });
  });

  // The provider can fetch our public keys here (register it as jwks_uri).
  app.get('/.well-known/jwks.json', (req, res) => {
    if (!rpKeys) return res.status(404).json({ error: 'no_keys', error_description: 'No PRIVATE_KEY_FILE configured.' });
    res.json(rpKeys.publicJwks);
  });

  // --- Frontend --------------------------------------------------------------

  app.use(express.static(publicDir, { index: false, maxAge: 0 }));
  app.use((req, res, next) => {
    // Client-side routes (/, /result) get the page; anything that looks like a file 404s.
    if (req.method !== 'GET' || req.path.startsWith('/api/') || path.extname(req.path)) return next();
    res.sendFile(path.join(publicDir, 'index.html'));
  });

  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    log.error('[http]', err);
    res.status(500).json({ error: 'internal_error', error_description: err.message });
  });

  return app;
}
