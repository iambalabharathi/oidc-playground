// The relying party, running in the browser: discovery, the code exchange with
// client authentication, ID token validation and UserInfo — on top of
// oauth4webapi (the engine behind openid-client) and jose for keys / JWE.
// Works against providers whose endpoints allow cross-origin requests from this page.
import * as oauth from '../vendor/oauth4webapi.js';
import * as jose from '../vendor/jose.js';

const decoder = new TextDecoder();
const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

export function isInsecureIssuer(issuer) {
  try {
    return new URL(issuer).protocol === 'http:';
  } catch {
    return false;
  }
}

function insecureOption(issuer) {
  if (!isInsecureIssuer(issuer)) return {};
  const host = new URL(issuer).hostname;
  if (!LOOPBACK.has(host)) throw new FlowError('insecure_issuer', 'http:// issuers are only accepted for localhost.', 'discovery');
  return { [oauth.allowInsecureRequests]: true };
}

export class FlowError extends Error {
  constructor(error, description, stage, extra = {}) {
    super(description);
    this.name = 'FlowError';
    this.error = error;
    this.error_description = description;
    this.stage = stage;
    Object.assign(this, extra);
  }
}

// --- discovery ------------------------------------------------------------------

export async function discover(issuer) {
  const url = new URL(issuer.replace(/\/+$/, ''));
  const response = await oauth.discoveryRequest(url, insecureOption(issuer)).catch((err) => {
    throw networkError(err, `${url.href}/.well-known/openid-configuration`, 'discovery');
  });
  const as = await oauth.processDiscoveryResponse(url, response);
  return { as, provider: summarize(as) };
}

function summarize(as) {
  return {
    issuer: as.issuer,
    endpoints: {
      authorization_endpoint: as.authorization_endpoint,
      token_endpoint: as.token_endpoint,
      userinfo_endpoint: as.userinfo_endpoint ?? null,
      jwks_uri: as.jwks_uri ?? null,
      end_session_endpoint: as.end_session_endpoint ?? null,
    },
    scopes_supported: as.scopes_supported ?? null,
    claims_supported: as.claims_supported ?? null,
    acr_values_supported: as.acr_values_supported ?? null,
    claims_parameter_supported: as.claims_parameter_supported ?? null,
    code_challenge_methods_supported: as.code_challenge_methods_supported ?? null,
    token_endpoint_auth_methods_supported: as.token_endpoint_auth_methods_supported ?? null,
    id_token_signing_alg_values_supported: as.id_token_signing_alg_values_supported ?? null,
    id_token_encryption_alg_values_supported: as.id_token_encryption_alg_values_supported ?? null,
    userinfo_signing_alg_values_supported: as.userinfo_signing_alg_values_supported ?? null,
    ui_locales_supported: as.ui_locales_supported ?? null,
  };
}

// --- keys -----------------------------------------------------------------------

const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth'];

/** Accepts a private JWK (object or JSON), a JWKS with one private key, or a PEM (PKCS#8) key. */
export async function parsePrivateKey(material) {
  let jwk;
  if (material && typeof material === 'object') {
    jwk = material.keys ? material.keys.find((k) => k.d) : material;
  } else {
    const text = String(material || '').trim();
    if (!text) throw new FlowError('invalid_private_key', 'No private key provided.', 'key');
    if (text.startsWith('{')) {
      let parsed;
      try {
        parsed = JSON.parse(text);
      } catch {
        throw new FlowError('invalid_private_key', 'The private key is not valid JSON.', 'key');
      }
      jwk = parsed.keys ? parsed.keys.find((k) => k.d) : parsed;
    } else if (text.includes('-----BEGIN')) {
      jwk = await pemToJwk(text);
    } else {
      throw new FlowError('invalid_private_key', 'Paste the private key as a JWK (JSON) or as PEM.', 'key');
    }
  }
  if (!jwk || !jwk.d) throw new FlowError('invalid_private_key', 'The JWK does not contain a private key (no "d" member).', 'key');

  const family = jwk.kty === 'EC' ? `EC:${jwk.crv}` : jwk.kty;
  const sigAlg = { RSA: 'RS256', 'EC:P-256': 'ES256', 'EC:P-384': 'ES384', 'EC:P-521': 'ES512' }[family];
  if (!sigAlg) throw new FlowError('invalid_private_key', `Unsupported key type ${family}; use an RSA or P-256/P-384/P-521 EC key.`, 'key');

  const publicJwk = Object.fromEntries(Object.entries(jwk).filter(([k]) => !PRIVATE_MEMBERS.includes(k) && !['key_ops'].includes(k)));
  let kid;
  try {
    kid = jwk.kid || (await jose.calculateJwkThumbprint(publicJwk));
  } catch (err) {
    throw new FlowError('invalid_private_key', `Invalid JWK: ${err.message}`, 'key');
  }
  const alg = jwk.alg && !jwk.alg.startsWith('RSA-OAEP') ? jwk.alg : sigAlg;

  let signingKey;
  try {
    signingKey = await jose.importJWK({ ...stripAlg(jwk) }, alg);
  } catch (err) {
    throw new FlowError('invalid_private_key', `The private key could not be imported: ${err.message}`, 'key');
  }

  const decryptionKeys = [];
  if (jwk.kty === 'RSA') {
    for (const encAlg of ['RSA-OAEP', 'RSA-OAEP-256']) {
      decryptionKeys.push({ alg: encAlg, key: await jose.importJWK(stripAlg(jwk), encAlg) });
    }
  }

  return {
    kid,
    alg,
    kty: jwk.kty,
    jwk,
    publicJwk: { ...publicJwk, kid, use: jwk.use || 'sig', alg },
    signingKey,
    decryptionKeys,
  };
}

function stripAlg(jwk) {
  const { alg, use, key_ops, ...rest } = jwk;
  return rest;
}

async function pemToJwk(pem) {
  let lastError;
  for (const alg of ['RS256', 'ES256', 'ES384', 'ES512']) {
    try {
      const key = await jose.importPKCS8(pem, alg, { extractable: true });
      return await jose.exportJWK(key);
    } catch (err) {
      lastError = err;
    }
  }
  throw new FlowError('invalid_private_key', `The PEM private key could not be read (PKCS#8 "BEGIN PRIVATE KEY" expected): ${lastError?.message || ''}`, 'key');
}

/** kid / alg / public JWK of a pasted private key — what the hosted JWKS must contain. */
export async function inspectKey(material) {
  const key = await parsePrivateKey(material);
  return { kid: key.kid, alg: key.alg, kty: key.kty, public_jwk: key.publicJwk };
}

async function clientAuthFor({ method, clientSecret, privateKey }) {
  switch (method) {
    case 'client_secret_post':
      return oauth.ClientSecretPost(clientSecret);
    case 'client_secret_basic':
      return oauth.ClientSecretBasic(clientSecret);
    case 'private_key_jwt':
      if (!privateKey) throw new FlowError('invalid_private_key', 'private_key_jwt needs the private key.', 'token');
      return oauth.PrivateKeyJwt({ key: privateKey.signingKey, kid: privateKey.kid });
    default:
      return oauth.None();
  }
}

function jweDecryptWith(privateKey) {
  return async (jwe) => {
    const header = jose.decodeProtectedHeader(jwe);
    const candidate = privateKey?.decryptionKeys.find((k) => k.alg === header.alg) || privateKey?.decryptionKeys[0];
    if (!candidate) {
      throw new oauth.OperationProcessingError(`The response is encrypted (${header.alg}) but no RSA private key was pasted.`, { code: 'OAUTH_DECRYPTION_FAILED' });
    }
    const { plaintext } = await jose.compactDecrypt(jwe, candidate.key, { keyManagementAlgorithms: [header.alg] }).catch((cause) => {
      throw new oauth.OperationProcessingError(`Decryption failed (${header.alg}${header.kid ? `, kid ${header.kid}` : ''}): check that the pasted key is the one the provider encrypts with.`, { cause, code: 'OAUTH_DECRYPTION_FAILED' });
    });
    return decoder.decode(plaintext);
  };
}

// --- code exchange --------------------------------------------------------------------

export async function exchangeCode({ as, clientId, auth, callbackUrl, redirectUri, expectedState, expectedNonce, codeVerifier, maxAge }) {
  const client = { client_id: clientId };
  const privateKey = auth.privateKeyMaterial ? await parsePrivateKey(auth.privateKeyMaterial) : null;
  const clientAuth = await clientAuthFor({ ...auth, privateKey });
  const insecure = insecureOption(as.issuer);

  const params = oauth.validateAuthResponse(as, client, new URL(callbackUrl), expectedState);
  const response = await oauth
    .authorizationCodeGrantRequest(as, client, clientAuth, params, redirectUri, codeVerifier || oauth.nopkce, insecure)
    .catch((err) => {
      throw networkError(err, as.token_endpoint, 'token');
    });
  const rawBody = await response.clone().text();

  const options = { requireIdToken: true, [oauth.jweDecrypt]: jweDecryptWith(privateKey) };
  if (expectedNonce) options.expectedNonce = expectedNonce;
  if (maxAge !== null && maxAge !== undefined) options.maxAge = maxAge;
  const tokens = await oauth.processAuthorizationCodeResponse(as, client, response, options);
  const payload = oauth.getValidatedIdTokenClaims(tokens);
  const decoded = decodeForDisplay(tokens.id_token);

  const checks = await idTokenChecks({ decoded, payload, tokens, expectedState, expectedNonce, codeVerifier, maxAge, jwksUri: as.jwks_uri });
  return {
    tokens: {
      token_type: tokens.token_type,
      expires_in: tokens.expires_in ?? null,
      scope: tokens.scope ?? null,
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token ?? null,
      id_token: tokens.id_token,
      receivedAt: new Date().toISOString(),
    },
    idToken: { format: decoded.format, header: decoded.header, payload, checks },
    endpoints: { token_endpoint: as.token_endpoint, userinfo_endpoint: as.userinfo_endpoint ?? null },
    raw: { status: response.status, body: rawBody.length > 20000 ? rawBody.slice(0, 20000) + '…' : rawBody },
  };
}

// --- userinfo -------------------------------------------------------------------------

export async function fetchUserinfo({ as, clientId, accessToken, expectedSub, privateKeyMaterial }) {
  if (!as.userinfo_endpoint) throw new FlowError('no_userinfo_endpoint', 'The provider metadata has no userinfo_endpoint.', 'userinfo');
  const client = { client_id: clientId };
  const privateKey = privateKeyMaterial ? await parsePrivateKey(privateKeyMaterial) : null;
  const started = Date.now();
  const response = await oauth.userInfoRequest(as, client, accessToken, insecureOption(as.issuer)).catch((err) => {
    throw networkError(err, as.userinfo_endpoint, 'userinfo');
  });
  const body = await response.clone().text();
  const contentType = response.headers.get('content-type') || '';
  const base = {
    request: { method: 'GET', url: as.userinfo_endpoint, headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json, application/jwt' } },
    response: {
      status: response.status,
      statusText: response.statusText,
      contentType,
      wwwAuthenticate: response.headers.get('www-authenticate'),
      body: body.length > 20000 ? body.slice(0, 20000) + '…' : body,
      durationMs: Date.now() - started,
    },
    fetchedAt: new Date().toISOString(),
  };

  const parts = body.trim().split('.');
  const isJwt = contentType.includes('application/jwt') || (parts.length === 3 || parts.length === 5) && /^[\w-]+$/.test(parts[0]);
  const format = !isJwt ? 'json' : parts.length === 5 ? 'jwe' : 'jwt';
  let header = null;
  if (isJwt) {
    try {
      header = jose.decodeProtectedHeader(body.trim());
    } catch {
      header = null;
    }
  }

  try {
    const claims = await oauth.processUserInfoResponse(as, client, expectedSub || oauth.skipSubjectCheck, response, { [oauth.jweDecrypt]: jweDecryptWith(privateKey) });
    const checks = [];
    if (format === 'jwe') checks.push({ title: 'Decrypted with the pasted private key', detail: `${header?.alg} · ${header?.enc}`, ok: true });
    if (format !== 'json') checks.push({ title: 'Signature verified', detail: `${header?.alg || 'JWS'}${header?.kid ? ` · kid ${header.kid}` : ''} · ${as.jwks_uri}`, ok: true });
    checks.push({ title: 'sub equals the ID token subject', detail: String(claims.sub), ok: true });
    const { iss, aud, exp, iat, nbf, jti, ...rest } = claims;
    return { ...base, ok: true, format, header, claims: rest, checks };
  } catch (err) {
    return { ...base, ok: false, format, header, error: describeError(err, 'userinfo') };
  }
}

// --- helpers --------------------------------------------------------------------------

function base64urlDecode(segment) {
  const padded = segment.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (segment.length % 4)) % 4);
  const bin = atob(padded);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function base64urlEncode(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function decodeForDisplay(token) {
  const parts = String(token || '').split('.');
  const json = (seg) => {
    try {
      return JSON.parse(decoder.decode(base64urlDecode(seg)));
    } catch {
      return null;
    }
  };
  if (parts.length === 5) return { format: 'jwe', header: json(parts[0]), payload: null };
  if (parts.length === 3) return { format: 'jws', header: json(parts[0]), payload: json(parts[1]) };
  return { format: 'opaque', header: null, payload: null };
}

async function computeAtHash(accessToken, alg = 'RS256') {
  const bits = String(alg).match(/(256|384|512)$/)?.[1] || '256';
  const digest = new Uint8Array(await crypto.subtle.digest(`SHA-${bits}`, new TextEncoder().encode(accessToken)));
  return base64urlEncode(digest.subarray(0, digest.length / 2));
}

async function idTokenChecks({ decoded, payload, tokens, expectedState, expectedNonce, codeVerifier, maxAge, jwksUri }) {
  const checks = [];
  const header = decoded.header || {};
  const now = Math.floor(Date.now() / 1000);
  checks.push({ title: 'state matches the request', detail: expectedState, ok: true });
  if (decoded.format === 'jwe') {
    checks.push({ title: 'Decrypted with the pasted private key', detail: `${header.alg} · ${header.enc}${header.kid ? ` · kid ${header.kid}` : ''}`, ok: true });
    checks.push({ title: 'Signature verified', detail: `nested JWS · ${jwksUri}`, ok: true });
  } else {
    checks.push({ title: 'Signature verified', detail: `${header.alg}${header.kid ? ` · kid ${header.kid}` : ''} · ${jwksUri}`, ok: true });
  }
  checks.push({ title: 'iss equals the issuer', detail: String(payload.iss), ok: true });
  checks.push({ title: 'aud contains client_id', detail: [].concat(payload.aud).join(', '), ok: true });
  if (expectedNonce) checks.push({ title: 'nonce matches the request', detail: String(payload.nonce), ok: true });
  if (codeVerifier) checks.push({ title: 'PKCE code_verifier accepted by the token endpoint', detail: 'S256', ok: true });
  checks.push({ title: 'exp is in the future', detail: `${formatTime(payload.exp)} · ${Math.max(0, payload.exp - now)} s left`, ok: payload.exp > now });
  if (payload.iat) checks.push({ title: 'iat is plausible', detail: formatTime(payload.iat), ok: payload.iat <= now + 300 });
  if (payload.auth_time && maxAge !== null && maxAge !== undefined) {
    checks.push({ title: `auth_time within max_age (${maxAge} s)`, detail: formatTime(payload.auth_time), ok: now - payload.auth_time <= maxAge + 60 });
  }
  if (payload.at_hash && decoded.format !== 'jwe') {
    const expected = await computeAtHash(tokens.access_token, header.alg);
    checks.push({ title: 'at_hash matches the access token', detail: expected === payload.at_hash ? payload.at_hash : `expected ${expected}, got ${payload.at_hash}`, ok: expected === payload.at_hash });
  }
  return checks;
}

function formatTime(seconds) {
  if (typeof seconds !== 'number') return String(seconds);
  return new Date(seconds * 1000).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
}

function networkError(err, url, stage) {
  if (err instanceof FlowError) return err;
  const inBrowser = typeof window !== 'undefined';
  const hint = inBrowser
    ? ' The browser could not complete the request: either the provider does not allow cross-origin (CORS) requests from this page, or the URL is unreachable. Switch "Exchange through" to the local helper if the provider has no CORS support.'
    : '';
  return new FlowError('network_error', `${err.message} while calling ${url}.${hint}`, stage, { cause: err });
}

/** Normalises oauth4webapi / jose / fetch errors into something the page can show. */
export function describeError(err, stage) {
  if (!err) return { error: 'unknown', error_description: 'Unknown error', stage };
  if (err instanceof FlowError) {
    return { error: err.error, error_description: err.error_description, stage: err.stage || stage, status: err.status };
  }
  if (err instanceof oauth.AuthorizationResponseError) {
    return { error: err.error, error_description: err.error_description || err.message, stage: 'authorization' };
  }
  if (err instanceof oauth.ResponseBodyError) {
    return { error: err.error, error_description: err.error_description || err.message, stage, status: err.status };
  }
  if (err instanceof oauth.WWWAuthenticateChallengeError) {
    const challenge = err.cause?.[0];
    return { error: challenge?.parameters?.error || 'www_authenticate', error_description: challenge?.parameters?.error_description || err.message, stage, status: err.status };
  }
  if (err instanceof oauth.OperationProcessingError || err instanceof oauth.UnsupportedOperationError) {
    const detail = err.cause instanceof Error ? `: ${err.cause.message}` : '';
    return { error: err.code || 'processing_error', error_description: `${err.message}${detail}`, stage };
  }
  return { error: err.code || err.name || 'unexpected_error', error_description: err.message, stage };
}
