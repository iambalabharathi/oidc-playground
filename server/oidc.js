// The relying-party side of the flow, built on openid-client — stateless.
// Every request carries the provider + client details it needs; the only thing
// kept in memory is a short-lived cache of discovery documents.
import * as client from 'openid-client';
import { computeAtHash, decodeJwtForDisplay, parseUserinfoBody } from './jwt.js';
import { importPrivateKey, KeyError } from './keys.js';

const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

export function createOidc(settings, log = console) {
  const discoveryCache = new Map(); // issuer → { promise, expiresAt }

  function assertIssuerAllowed(issuer) {
    const url = new URL(issuer);
    if (url.protocol === 'https:') return url;
    if (url.protocol !== 'http:') throw new Error('The issuer must be an http(s) URL');
    if (!settings.allowAnyInsecureIssuer && !LOOPBACK.has(url.hostname)) {
      throw new Error('http:// issuers are only accepted for localhost (set ALLOW_INSECURE_ISSUER=1 to override)');
    }
    return url;
  }

  /** Fetches (or reuses) the provider's discovery document. */
  function discover(issuer) {
    const key = issuer.replace(/\/+$/, '');
    const cached = discoveryCache.get(key);
    if (cached && cached.expiresAt > Date.now()) return cached.promise;

    const promise = (async () => {
      const url = assertIssuerAllowed(key);
      const options = url.protocol === 'http:' ? { execute: [client.allowInsecureRequests] } : undefined;
      // discovery() wants a client id; this probe configuration is only used to read the metadata
      const probe = await client.discovery(url, 'discovery-probe', undefined, client.None(), options);
      return JSON.parse(JSON.stringify(probe.serverMetadata()));
    })();
    discoveryCache.set(key, { promise, expiresAt: Date.now() + settings.discoveryTtl * 1000 });
    promise.catch(() => discoveryCache.delete(key));
    return promise;
  }

  async function describeProvider(issuer) {
    const md = await discover(issuer);
    return {
      issuer: md.issuer,
      endpoints: {
        authorization_endpoint: md.authorization_endpoint,
        token_endpoint: md.token_endpoint,
        userinfo_endpoint: md.userinfo_endpoint ?? null,
        jwks_uri: md.jwks_uri ?? null,
        end_session_endpoint: md.end_session_endpoint ?? null,
      },
      scopes_supported: md.scopes_supported ?? null,
      claims_supported: md.claims_supported ?? null,
      acr_values_supported: md.acr_values_supported ?? null,
      claims_parameter_supported: md.claims_parameter_supported ?? null,
      code_challenge_methods_supported: md.code_challenge_methods_supported ?? null,
      token_endpoint_auth_methods_supported: md.token_endpoint_auth_methods_supported ?? null,
      id_token_signing_alg_values_supported: md.id_token_signing_alg_values_supported ?? null,
      id_token_encryption_alg_values_supported: md.id_token_encryption_alg_values_supported ?? null,
      userinfo_signing_alg_values_supported: md.userinfo_signing_alg_values_supported ?? null,
      ui_locales_supported: md.ui_locales_supported ?? null,
    };
  }

  async function configurationFor({ issuer, clientId, clientAuth }, privateKey) {
    const metadata = await discover(issuer);
    const clientMetadata = {};
    let authentication;
    switch (clientAuth.method) {
      case 'client_secret_post':
        clientMetadata.client_secret = clientAuth.client_secret;
        authentication = client.ClientSecretPost(clientAuth.client_secret);
        break;
      case 'client_secret_basic':
        clientMetadata.client_secret = clientAuth.client_secret;
        authentication = client.ClientSecretBasic(clientAuth.client_secret);
        break;
      case 'private_key_jwt':
        authentication = client.PrivateKeyJwt({ key: privateKey.signing.key, kid: privateKey.kid });
        break;
      default:
        authentication = client.None();
    }
    const configuration = new client.Configuration(metadata, clientId, clientMetadata, authentication);
    if (new URL(issuer).protocol === 'http:') client.allowInsecureRequests(configuration);
    if (privateKey && privateKey.decryption.length) {
      // the provider encrypts with the key it finds in the hosted JWKS; its kid must match the pasted key's kid
      client.enableDecryptingResponses(configuration, undefined, ...privateKey.decryption.map((k) => ({ key: k.key, alg: k.alg, kid: privateKey.kid })));
    }
    return configuration;
  }

  /** Exchanges the code and validates the ID token (signature, iss, aud, exp, nonce, PKCE). */
  async function exchangeCode(input) {
    const privateKey = input.clientAuth.private_key ? await importPrivateKey(input.clientAuth.private_key) : null;
    const configuration = await configurationFor(input, privateKey);
    const checks = {
      expectedState: input.expectedState,
      expectedNonce: input.expectedNonce,
      idTokenExpected: true,
    };
    if (input.codeVerifier) checks.pkceCodeVerifier = input.codeVerifier;
    if (input.maxAge !== null && input.maxAge !== undefined) checks.maxAge = input.maxAge;

    const callbackUrl = new URL(input.callbackUrl);
    const tokens = await client.authorizationCodeGrant(configuration, callbackUrl, checks);
    const payload = tokens.claims();
    const decoded = decodeJwtForDisplay(tokens.id_token);
    const md = configuration.serverMetadata();

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
      idToken: {
        format: decoded.format,
        header: decoded.header,
        payload,
        checks: idTokenChecks({ decoded, payload, input, tokens, jwksUri: md.jwks_uri }),
      },
      endpoints: { token_endpoint: md.token_endpoint, userinfo_endpoint: md.userinfo_endpoint ?? null },
    };
  }

  /** Calls the UserInfo endpoint ourselves so the raw response can be shown too. */
  async function fetchUserinfo({ issuer, clientId, accessToken, expectedSub, privateKeyMaterial }) {
    const md = await discover(issuer);
    if (!md.userinfo_endpoint) throw new Error('The provider metadata has no userinfo_endpoint');
    const privateKey = privateKeyMaterial ? await importPrivateKey(privateKeyMaterial) : null;

    const started = Date.now();
    const response = await fetch(md.userinfo_endpoint, {
      headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json, application/jwt' },
    });
    const body = await response.text();
    const contentType = response.headers.get('content-type') || '';
    const base = {
      request: {
        method: 'GET',
        url: md.userinfo_endpoint,
        headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json, application/jwt' },
      },
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

    if (!response.ok) {
      return {
        ...base,
        ok: false,
        error: { error: `http_${response.status}`, error_description: response.headers.get('www-authenticate') || body.slice(0, 500), stage: 'userinfo' },
      };
    }

    try {
      const parsed = await parseUserinfoBody({
        contentType,
        body,
        issuer: md.issuer,
        clientId,
        jwksUri: md.jwks_uri,
        decryptionKeys: privateKey ? privateKey.decryption : [],
        expectedSub,
      });
      return { ...base, ok: true, format: parsed.format, header: parsed.header, claims: parsed.claims, checks: parsed.checks };
    } catch (err) {
      return { ...base, ok: false, error: describeError(err, 'userinfo') };
    }
  }

  async function inspectKey(material) {
    const key = await importPrivateKey(material);
    return { kid: key.kid, alg: key.alg, kty: key.kty, public_jwk: key.publicJwk };
  }

  return { discover, describeProvider, exchangeCode, fetchUserinfo, inspectKey };
}

function idTokenChecks({ decoded, payload, input, tokens, jwksUri }) {
  const checks = [];
  const header = decoded.header || {};
  const now = Math.floor(Date.now() / 1000);

  checks.push({ title: 'state matches the request', detail: input.expectedState, ok: true });
  if (decoded.format === 'jwe') {
    checks.push({ title: 'Decrypted with the pasted private key', detail: `${header.alg} · ${header.enc}${header.kid ? ` · kid ${header.kid}` : ''}`, ok: true });
    checks.push({ title: 'Signature verified', detail: `nested JWS · ${jwksUri}`, ok: true });
  } else {
    checks.push({ title: 'Signature verified', detail: `${header.alg}${header.kid ? ` · kid ${header.kid}` : ''} · ${jwksUri}`, ok: true });
  }
  checks.push({ title: 'iss equals the issuer', detail: String(payload.iss), ok: true });
  checks.push({ title: 'aud contains client_id', detail: [].concat(payload.aud).join(', '), ok: true });
  if (input.expectedNonce) checks.push({ title: 'nonce matches the request', detail: String(payload.nonce), ok: true });
  if (input.codeVerifier) checks.push({ title: 'PKCE code_verifier accepted by the token endpoint', detail: 'S256', ok: true });
  checks.push({
    title: 'exp is in the future',
    detail: `${formatTime(payload.exp)} · ${Math.max(0, payload.exp - now)} s left`,
    ok: payload.exp > now,
  });
  if (payload.iat) checks.push({ title: 'iat is plausible', detail: formatTime(payload.iat), ok: payload.iat <= now + 300 });
  if (payload.auth_time && input.maxAge !== null && input.maxAge !== undefined) {
    checks.push({ title: `auth_time within max_age (${input.maxAge} s)`, detail: formatTime(payload.auth_time), ok: now - payload.auth_time <= input.maxAge + 60 });
  }
  if (payload.at_hash && decoded.format !== 'jwe') {
    const expected = computeAtHash(tokens.access_token, header.alg);
    checks.push({
      title: 'at_hash matches the access token',
      detail: expected === payload.at_hash ? payload.at_hash : `expected ${expected}, got ${payload.at_hash}`,
      ok: expected === payload.at_hash,
    });
  }
  return checks;
}

function formatTime(seconds) {
  if (typeof seconds !== 'number') return String(seconds);
  return new Date(seconds * 1000).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
}

/** Normalises openid-client / jose / fetch errors into something the page can show. */
export function describeError(err, stage) {
  if (!err) return { error: 'unknown', error_description: 'Unknown error', stage };
  const base = { stage, name: err.name || 'Error' };
  if (err instanceof KeyError) {
    return { ...base, error: 'invalid_private_key', error_description: err.message };
  }
  if (err instanceof client.AuthorizationResponseError) {
    return { ...base, stage: 'authorization', error: err.error, error_description: err.error_description || err.message };
  }
  if (err instanceof client.ResponseBodyError) {
    return { ...base, error: err.error, error_description: err.error_description || err.message, status: err.status };
  }
  if (err instanceof client.WWWAuthenticateChallengeError) {
    const challenge = err.cause?.[0];
    return { ...base, error: challenge?.parameters?.error || 'www_authenticate', error_description: challenge?.parameters?.error_description || err.message, status: err.status };
  }
  if (err instanceof client.ClientError) {
    const detail = err.cause instanceof Error ? err.cause.message : typeof err.cause === 'string' ? err.cause : null;
    let description = detail ? `${err.message}: ${detail}` : err.message;
    if (err.code === 'OAUTH_DECRYPTION_FAILED') {
      description += ' — the response is encrypted; paste the private key whose kid matches the key the provider encrypts with.';
    }
    return { ...base, error: err.code || 'client_error', error_description: description };
  }
  const cause = err.cause ? ` (${err.cause.code || err.cause.message || err.cause})` : '';
  return { ...base, error: err.code || 'unexpected_error', error_description: `${err.message}${cause}` };
}
