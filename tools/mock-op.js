#!/usr/bin/env node
// A deliberately small OpenID Provider for trying the playground without real
// credentials: discovery, authorization (with a consent page), token endpoint
// with PKCE + client_secret_post/basic, RS256 ID tokens, UserInfo as JSON or JWT.
// Not a reference implementation — just enough to exercise the relying party.
import express from 'express';
import { randomBytes, createHash } from 'node:crypto';
import * as jose from 'jose';

const ITSME = 'http://itsme.services/v2/claim/';

export const PERSONA = {
  sub: 'k2Vq8LXf0b3nR9yTqW5pHs7dZc1mJ4uA6eGvN0xB8Yw=',
  name: 'Lotte Vermeulen',
  given_name: 'Lotte',
  family_name: 'Vermeulen',
  middle_name: 'Marie',
  nickname: 'Lot',
  preferred_username: 'lotte.v',
  profile: 'https://example.com/lotte',
  picture: 'https://example.com/lotte.jpg',
  website: 'https://example.com',
  gender: 'female',
  birthdate: '1991-04-23',
  zoneinfo: 'Europe/Brussels',
  locale: 'nl',
  updated_at: 1794000000,
  email: 'lotte.vermeulen@example.com',
  email_verified: true,
  phone_number: '+32470123456',
  phone_number_verified: true,
  address: {
    formatted: 'Kerkstraat 12\n2000 Antwerpen\nBelgium',
    street_address: 'Kerkstraat 12',
    locality: 'Antwerpen',
    postal_code: '2000',
    country: 'BE',
  },
  [ITSME + 'BENationalNumber']: '91042312458',
  [ITSME + 'BEeidSn']: '592123456789',
  [ITSME + 'place_of_birth']: 'Antwerpen',
  [ITSME + 'claim_citizenship']: 'Belg',
  [ITSME + 'claim_citizenship_as_iso']: 'BEL',
  [ITSME + 'claim_device']: { os: 'iOS', appName: 'itsme', appRelease: '7.1.0', deviceLabel: 'iPhone', deviceModel: 'iPhone16,1', osRelease: '19.1' },
  [ITSME + 'IDDocumentType']: 'eID',
  [ITSME + 'IDDocumentSN']: '592123456789',
  [ITSME + 'validityTo']: { year: 2031, month: 4, day: 22 },
};

const SCOPE_CLAIMS = {
  profile: ['name', 'given_name', 'family_name', 'middle_name', 'nickname', 'preferred_username', 'profile', 'picture', 'website', 'gender', 'birthdate', 'zoneinfo', 'locale', 'updated_at'],
  email: ['email', 'email_verified'],
  phone: ['phone_number', 'phone_number_verified'],
  address: ['address'],
  eid: [ITSME + 'BENationalNumber', ITSME + 'BEeidSn'],
};

const ACR_BASIC = ITSME + 'acr_basic';
const ACR_ADVANCED = ITSME + 'acr_advanced';

export async function startMockOp(options = {}) {
  const port = Number(options.port ?? process.env.MOCK_OP_PORT ?? 9000);
  const clientId = options.clientId ?? process.env.MOCK_OP_CLIENT_ID ?? 'playground';
  const clientSecret = options.clientSecret ?? process.env.MOCK_OP_CLIENT_SECRET ?? 'secret';
  const autoApprove = options.autoApprove ?? flag(process.env.MOCK_OP_AUTO_APPROVE);
  const userinfoJwt = options.userinfoJwt ?? flag(process.env.MOCK_OP_USERINFO_JWT);
  const omit = options.omit ?? (process.env.MOCK_OP_OMIT ?? 'gender').split(',').map((s) => s.trim()).filter(Boolean);
  // private_key_jwt support: where to fetch the relying party's public keys from
  let clientJwksUri = options.clientJwksUri ?? process.env.MOCK_OP_CLIENT_JWKS_URI ?? null;
  // encrypt responses for the client with its "enc" key from that JWKS (JWE RSA-OAEP / A128CBC-HS256)
  const encryptIdToken = options.encryptIdToken ?? flag(process.env.MOCK_OP_ENCRYPT_ID_TOKEN);
  const encryptUserinfo = options.encryptUserinfo ?? flag(process.env.MOCK_OP_ENCRYPT_USERINFO);
  const log = options.quiet ? () => {} : (...args) => console.log('[mock-op]', ...args);

  const { publicKey, privateKey } = await jose.generateKeyPair('RS256', { extractable: true });
  const kid = 'mock-' + randomBytes(3).toString('hex');
  const publicJwk = { ...(await jose.exportJWK(publicKey)), kid, use: 'sig', alg: 'RS256' };

  const transactions = new Map(); // txnId → { params, createdAt, code, used }
  const codes = new Map(); // code → txnId
  const accessTokens = new Map(); // token → { sub, scopes, userinfoClaims, exp }

  const app = express();
  app.disable('x-powered-by');
  app.use(express.urlencoded({ extended: false }));

  let issuer = `http://localhost:${port}`;
  const metadata = () => ({
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    userinfo_endpoint: `${issuer}/userinfo`,
    jwks_uri: `${issuer}/jwks`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    userinfo_signing_alg_values_supported: ['RS256'],
    scopes_supported: ['openid', 'profile', 'email', 'phone', 'address', 'eid', 'offline_access'],
    claims_supported: ['sub', ...Object.keys(PERSONA).filter((k) => k !== 'sub')],
    claims_parameter_supported: true,
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic', 'private_key_jwt'],
    token_endpoint_auth_signing_alg_values_supported: ['RS256', 'ES256'],
    id_token_encryption_alg_values_supported: ['RSA-OAEP', 'RSA-OAEP-256'],
    id_token_encryption_enc_values_supported: ['A128CBC-HS256'],
    userinfo_encryption_alg_values_supported: ['RSA-OAEP', 'RSA-OAEP-256'],
    userinfo_encryption_enc_values_supported: ['A128CBC-HS256'],
    acr_values_supported: [ACR_BASIC, ACR_ADVANCED],
    ui_locales_supported: ['nl', 'fr', 'de', 'en'],
  });

  app.get('/.well-known/openid-configuration', (req, res) => res.json(metadata()));
  app.get('/jwks', (req, res) => res.json({ keys: [publicJwk] }));

  app.get('/authorize', (req, res) => {
    const q = req.query;
    const fail = (error, error_description) => {
      if (q.redirect_uri && isUrl(q.redirect_uri)) {
        const u = new URL(q.redirect_uri);
        u.searchParams.set('error', error);
        u.searchParams.set('error_description', error_description);
        if (q.state) u.searchParams.set('state', q.state);
        return res.redirect(302, u.href);
      }
      return res.status(400).send(`${error}: ${error_description}`);
    };

    if (q.client_id !== clientId) return res.status(400).send(`unknown client_id (expected "${clientId}")`);
    if (!q.redirect_uri || !isUrl(q.redirect_uri)) return res.status(400).send('redirect_uri is required');
    if (q.response_type !== 'code') return fail('unsupported_response_type', 'only response_type=code is supported');
    const scopes = String(q.scope || '').split(/\s+/).filter(Boolean);
    if (!scopes.includes('openid')) return fail('invalid_scope', 'scope must include openid');
    let claims = null;
    if (q.claims) {
      try {
        claims = JSON.parse(q.claims);
      } catch {
        return fail('invalid_request', 'claims is not valid JSON');
      }
    }
    if (q.code_challenge && q.code_challenge_method && q.code_challenge_method !== 'S256') {
      return fail('invalid_request', 'only code_challenge_method=S256 is supported');
    }
    if (q.prompt === 'none') return fail('login_required', 'prompt=none: the mock provider has no session to reuse');

    const txnId = randomBytes(12).toString('base64url');
    transactions.set(txnId, { params: { ...q, scopes, claims }, createdAt: Date.now(), code: null, used: false });
    log(`authorize → scopes [${scopes.join(' ')}]${claims ? ' + claims parameter' : ''}`);

    if (autoApprove || q.auto === '1') return res.redirect(302, decide(txnId, 'approve'));
    res.type('html').send(consentPage({
      scopes,
      claims,
      acr: q.acr_values,
      approveUrl: `/authorize/decision?txn=${txnId}&d=approve`,
      denyUrl: `/authorize/decision?txn=${txnId}&d=deny`,
    }));
  });

  // The consent page posts the user's decision here; only an approval mints a code.
  app.get('/authorize/decision', (req, res) => {
    const txn = transactions.get(String(req.query.txn || ''));
    if (!txn) return res.status(400).send('unknown or expired transaction');
    res.redirect(302, decide(String(req.query.txn), req.query.d === 'approve' ? 'approve' : 'deny'));
  });

  function decide(txnId, decision) {
    const txn = transactions.get(txnId);
    const u = new URL(txn.params.redirect_uri);
    if (decision === 'approve') {
      txn.code = randomBytes(16).toString('base64url');
      codes.set(txn.code, txnId);
      u.searchParams.set('code', txn.code);
    } else {
      transactions.delete(txnId);
      u.searchParams.set('error', 'access_denied');
      u.searchParams.set('error_description', 'The user declined the request');
    }
    if (txn.params.state) u.searchParams.set('state', txn.params.state);
    u.searchParams.set('iss', issuer);
    return u.href;
  }

  app.post('/token', async (req, res) => {
    const b = req.body;
    const fail = (status, error, error_description) => res.status(status).json({ error, error_description });

    // client authentication: private_key_jwt, client_secret_post or client_secret_basic
    if (b.client_assertion_type === 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer') {
      if (!clientJwksUri) return fail(401, 'invalid_client', 'private_key_jwt is not configured on the mock (MOCK_OP_CLIENT_JWKS_URI)');
      try {
        const RP_JWKS = jose.createRemoteJWKSet(new URL(clientJwksUri));
        await jose.jwtVerify(b.client_assertion, RP_JWKS, { issuer: clientId, subject: clientId, audience: [issuer, `${issuer}/token`] });
        log('token ← client authenticated with private_key_jwt');
      } catch (err) {
        return fail(401, 'invalid_client', `client_assertion rejected: ${err.message}`);
      }
    } else {
      let presentedId = b.client_id;
      let presentedSecret = b.client_secret;
      const basic = req.headers.authorization?.match(/^Basic (.+)$/i);
      if (basic) {
        const [id, secret] = Buffer.from(basic[1], 'base64').toString('utf8').split(':').map(decodeURIComponent);
        presentedId = id;
        presentedSecret = secret;
      }
      if (presentedId !== clientId || presentedSecret !== clientSecret) {
        return fail(401, 'invalid_client', 'client authentication failed (expected client_secret_post, client_secret_basic or private_key_jwt)');
      }
    }
    if (b.grant_type !== 'authorization_code') return fail(400, 'unsupported_grant_type', 'only authorization_code is supported');

    const txn = transactions.get(codes.get(String(b.code || '')));
    if (!txn || txn.used) return fail(400, 'invalid_grant', 'unknown or already used authorization code');
    if (Date.now() - txn.createdAt > 5 * 60 * 1000) return fail(400, 'invalid_grant', 'authorization code expired');
    if (b.redirect_uri !== txn.params.redirect_uri) return fail(400, 'invalid_grant', 'redirect_uri does not match the authorization request');
    if (txn.params.code_challenge) {
      if (!b.code_verifier) return fail(400, 'invalid_grant', 'code_verifier is required (PKCE)');
      const challenge = createHash('sha256').update(b.code_verifier).digest('base64url');
      if (challenge !== txn.params.code_challenge) return fail(400, 'invalid_grant', 'PKCE verification failed');
    }
    txn.used = true;

    const { scopes, claims, nonce, acr_values } = txn.params;
    const now = Math.floor(Date.now() / 1000);
    const accessToken = randomBytes(24).toString('base64url');
    const requestedAcr = String(acr_values || '').split(/\s+/).filter(Boolean)[0];
    const acr = [ACR_BASIC, ACR_ADVANCED].includes(requestedAcr) ? requestedAcr : ACR_BASIC;

    const idTokenClaims = {
      iss: issuer,
      sub: PERSONA.sub,
      aud: clientId,
      exp: now + 300,
      iat: now,
      auth_time: now - 30,
      acr,
      at_hash: createHash('sha256').update(accessToken).digest().subarray(0, 16).toString('base64url'),
      ...pickClaims(scopes, claims?.id_token, omit),
    };
    if (nonce) idTokenClaims.nonce = nonce;

    let idToken = await new jose.SignJWT(idTokenClaims)
      .setProtectedHeader({ alg: 'RS256', kid, typ: 'JWT' })
      .sign(privateKey);
    if (encryptIdToken) {
      try {
        idToken = await encryptForClient(idToken);
      } catch (err) {
        return fail(500, 'server_error', `cannot encrypt the ID token: ${err.message}`);
      }
    }

    accessTokens.set(accessToken, {
      sub: PERSONA.sub,
      claims: { sub: PERSONA.sub, ...pickClaims(scopes, claims?.userinfo, omit) },
      exp: now + 300,
    });
    log(`token → id_token with ${Object.keys(idTokenClaims).length} claims`);

    const response = {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 300,
      scope: scopes.join(' '),
      id_token: idToken,
    };
    if (scopes.includes('offline_access')) response.refresh_token = randomBytes(24).toString('base64url');
    res.json(response);
  });

  app.get('/userinfo', async (req, res) => {
    const m = req.headers.authorization?.match(/^Bearer (.+)$/i);
    const entry = m && accessTokens.get(m[1]);
    if (!entry) {
      res.set('WWW-Authenticate', 'Bearer error="invalid_token", error_description="unknown access token"');
      return res.status(401).json({ error: 'invalid_token' });
    }
    if (entry.exp < Math.floor(Date.now() / 1000)) {
      res.set('WWW-Authenticate', 'Bearer error="invalid_token", error_description="access token expired"');
      return res.status(401).json({ error: 'invalid_token' });
    }
    log(`userinfo → ${Object.keys(entry.claims).length} claims as ${userinfoJwt ? 'JWT' : 'JSON'}`);
    if (userinfoJwt || encryptUserinfo) {
      let jwt = await new jose.SignJWT({ ...entry.claims, iss: issuer, aud: clientId })
        .setProtectedHeader({ alg: 'RS256', kid })
        .setIssuedAt()
        .sign(privateKey);
      if (encryptUserinfo) jwt = await encryptForClient(jwt);
      return res.type('application/jwt').send(jwt);
    }
    res.json(entry.claims);
  });

  async function encryptForClient(jws) {
    if (!clientJwksUri) throw new Error('no client JWKS URI configured (MOCK_OP_CLIENT_JWKS_URI)');
    const jwks = await (await fetch(clientJwksUri)).json();
    const encJwk = jwks.keys.find((k) => k.use === 'enc' && k.kty === 'RSA') || jwks.keys.find((k) => k.kty === 'RSA');
    if (!encJwk) throw new Error('the client JWKS has no RSA key to encrypt with');
    const key = await jose.importJWK({ ...encJwk, alg: 'RSA-OAEP' }, 'RSA-OAEP');
    return new jose.CompactEncrypt(new TextEncoder().encode(jws))
      .setProtectedHeader({ alg: 'RSA-OAEP', enc: 'A128CBC-HS256', cty: 'JWT', kid: encJwk.kid })
      .encrypt(key);
  }

  const server = await new Promise((resolve) => {
    const s = app.listen(port, '127.0.0.1', () => resolve(s));
  });
  issuer = `http://localhost:${server.address().port}`;
  log(`listening on ${issuer}  (client_id "${clientId}", secret "${clientSecret}", auto-approve ${autoApprove ? 'on' : 'off'})`);

  return {
    server,
    issuer,
    clientId,
    clientSecret,
    setClientJwksUri(uri) {
      clientJwksUri = uri;
    },
    close: () => {
      server.closeAllConnections();
      return new Promise((resolve) => server.close(resolve));
    },
  };
}

function pickClaims(scopes, requested, omit) {
  const names = new Set();
  for (const scope of scopes) for (const name of SCOPE_CLAIMS[scope] || []) names.add(name);
  for (const name of Object.keys(requested || {})) names.add(name);
  const out = {};
  for (const name of names) {
    if (omit.includes(name) || omit.includes(name.replace(ITSME, ''))) continue;
    if (name in PERSONA && name !== 'sub') out[name] = PERSONA[name];
  }
  return out;
}

function flag(value) {
  return ['1', 'true', 'yes', 'on'].includes(String(value ?? '').toLowerCase());
}

function isUrl(value) {
  try {
    new URL(value);
    return true;
  } catch {
    return false;
  }
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

function consentPage({ scopes, claims, acr, approveUrl, denyUrl }) {
  const claimNames = new Set();
  for (const target of ['id_token', 'userinfo']) for (const n of Object.keys(claims?.[target] || {})) claimNames.add(n);
  const list = (items) => (items.length ? `<ul>${items.map((i) => `<li><code>${esc(i)}</code></li>`).join('')}</ul>` : '<p class="muted">none</p>');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Mock OP · consent</title>
<meta name="viewport" content="width=device-width, initial-scale=1"><link rel="icon" href="data:,">
<style>
body{margin:0;background:#141821;color:#E6E8F0;font:15px/1.5 Inter,system-ui,sans-serif;display:flex;justify-content:center;padding:40px 16px}
main{width:100%;max-width:520px;background:#1C2130;border:1px solid #2A3144;border-radius:16px;padding:28px}
h1{margin:0 0 4px;font-size:22px}.muted{color:#A3ACBE;margin:0}
h2{font-size:13px;letter-spacing:.06em;text-transform:uppercase;color:#A3ACBE;margin:22px 0 6px}
ul{margin:0;padding-left:20px}code{font:13px "JetBrains Mono",ui-monospace,monospace}
.actions{display:flex;gap:10px;margin-top:28px}
a.btn{flex:1;text-align:center;padding:12px;border-radius:10px;text-decoration:none;font-weight:600}
a.approve{background:#6366F1;color:#fff}a.deny{border:1px solid #3B4257;color:#E6E8F0}
</style></head><body><main>
<h1>Mock OpenID Provider</h1><p class="muted">The playground asks you to share:</p>
<h2>Scopes</h2>${list(scopes)}
<h2>Individual claims</h2>${list([...claimNames])}
${acr ? `<h2>Authentication level</h2><p><code>${esc(acr)}</code></p>` : ''}
<div class="actions"><a class="btn approve" href="${esc(approveUrl)}">Approve as Lotte Vermeulen</a><a class="btn deny" href="${esc(denyUrl)}">Deny</a></div>
</main></body></html>`;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  startMockOp().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
