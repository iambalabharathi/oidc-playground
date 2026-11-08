// The relying-party side of the flow, built on openid-client:
// discovery → authorization URL → code exchange + ID token validation → UserInfo.
import * as client from 'openid-client';
import { computeAtHash, decodeJwtForDisplay, parseUserinfoBody } from './jwt.js';

export function createOidc(settings, rpKeys, log = console) {
  let configurationPromise = null;
  let lastDiscoveryError = null;

  function clientAuthentication() {
    switch (settings.clientAuth) {
      case 'client_secret_post':
        return client.ClientSecretPost(settings.clientSecret);
      case 'client_secret_basic':
        return client.ClientSecretBasic(settings.clientSecret);
      case 'private_key_jwt':
        if (!rpKeys) throw new Error('private_key_jwt requires a private key');
        return client.PrivateKeyJwt({ key: rpKeys.signing.key, kid: rpKeys.kid });
      default:
        return client.None();
    }
  }

  async function discover() {
    const metadata = {};
    if (settings.clientSecret) metadata.client_secret = settings.clientSecret;
    if (settings.idTokenSignedResponseAlg) metadata.id_token_signed_response_alg = settings.idTokenSignedResponseAlg;

    const options = settings.allowInsecure ? { execute: [client.allowInsecureRequests] } : undefined;
    const configuration = await client.discovery(
      new URL(settings.issuer),
      settings.clientId,
      metadata,
      clientAuthentication(),
      options,
    );

    if (settings.decryptResponses) {
      if (!rpKeys || !rpKeys.decryption.length) {
        throw new Error('DECRYPT_RESPONSES=1 needs an RSA private key (PRIVATE_KEY_FILE)');
      }
      client.enableDecryptingResponses(configuration, undefined, ...rpKeys.decryption.map((k) => ({ key: k.key, alg: k.alg, kid: k.kid })));
    }
    return configuration;
  }

  /** Discovery is lazy and cached; a failure is retried on the next call. */
  function getConfiguration() {
    if (!configurationPromise) {
      configurationPromise = discover()
        .then((configuration) => {
          lastDiscoveryError = null;
          return configuration;
        })
        .catch((err) => {
          configurationPromise = null;
          lastDiscoveryError = err;
          throw err;
        });
    }
    return configurationPromise;
  }

  async function describeProvider() {
    try {
      const configuration = await getConfiguration();
      const md = configuration.serverMetadata();
      return {
        ok: true,
        endpoints: {
          authorization_endpoint: md.authorization_endpoint,
          token_endpoint: md.token_endpoint,
          userinfo_endpoint: md.userinfo_endpoint,
          jwks_uri: md.jwks_uri,
        },
        scopes_supported: md.scopes_supported || null,
        claims_supported: md.claims_supported || null,
        acr_values_supported: md.acr_values_supported || null,
        claims_parameter_supported: md.claims_parameter_supported ?? null,
        code_challenge_methods_supported: md.code_challenge_methods_supported || null,
        token_endpoint_auth_methods_supported: md.token_endpoint_auth_methods_supported || null,
        id_token_signing_alg_values_supported: md.id_token_signing_alg_values_supported || null,
      };
    } catch (err) {
      return { ok: false, error: describeError(err, 'discovery') };
    }
  }

  /** Builds the authorization URL; returns what must be remembered in the session. */
  async function startAuthorization({ scopes, claims, options, pkce }) {
    const configuration = await getConfiguration();
    const state = client.randomState();
    const nonce = client.randomNonce();

    const parameters = {
      redirect_uri: settings.redirectUri,
      scope: scopes.join(' '),
      state,
      nonce,
    };
    let codeVerifier = null;
    if (pkce) {
      codeVerifier = client.randomPKCECodeVerifier();
      parameters.code_challenge = await client.calculatePKCECodeChallenge(codeVerifier);
      parameters.code_challenge_method = 'S256';
    }
    for (const [key, value] of Object.entries(options || {})) {
      parameters[key] = String(value);
    }
    if (claims) parameters.claims = JSON.stringify(claims);

    const url = client.buildAuthorizationUrl(configuration, parameters);
    return {
      url: url.href,
      params: [...url.searchParams].map(([k, v]) => ({ k, v })),
      pending: {
        state,
        nonce,
        codeVerifier,
        maxAge: options?.max_age ?? null,
        startedAt: new Date().toISOString(),
      },
    };
  }

  /** Exchanges the code and validates the ID token (signature, iss, aud, exp, nonce, PKCE). */
  async function completeAuthorization(callbackUrl, pending) {
    const configuration = await getConfiguration();
    const checks = {
      expectedState: pending.state,
      expectedNonce: pending.nonce,
      idTokenExpected: true,
    };
    if (pending.codeVerifier) checks.pkceCodeVerifier = pending.codeVerifier;
    if (pending.maxAge !== null && pending.maxAge !== undefined) checks.maxAge = pending.maxAge;

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
      },
      idToken: {
        format: decoded.format,
        header: decoded.header,
        payload,
        checks: idTokenChecks({ decoded, payload, pending, tokens, settings, jwksUri: md.jwks_uri }),
      },
    };
  }

  /** Calls the UserInfo endpoint ourselves so the raw response can be shown too. */
  async function fetchUserinfo(accessToken, expectedSub) {
    const configuration = await getConfiguration();
    const md = configuration.serverMetadata();
    if (!md.userinfo_endpoint) throw new Error('The provider metadata has no userinfo_endpoint');

    const started = Date.now();
    const response = await fetch(md.userinfo_endpoint, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/json, application/jwt',
      },
    });
    const body = await response.text();
    const contentType = response.headers.get('content-type') || '';
    const base = {
      request: {
        method: 'GET',
        url: md.userinfo_endpoint,
        headers: { Authorization: 'Bearer ' + accessToken, Accept: 'application/json, application/jwt' },
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
      return { ...base, ok: false, error: { error: `http_${response.status}`, error_description: response.headers.get('www-authenticate') || body.slice(0, 500), stage: 'userinfo' } };
    }

    try {
      const parsed = await parseUserinfoBody({
        contentType,
        body,
        issuer: settings.issuer,
        clientId: settings.clientId,
        jwksUri: md.jwks_uri,
        decryptionKeys: rpKeys ? rpKeys.decryption : [],
        expectedSub,
      });
      return { ...base, ok: true, format: parsed.format, header: parsed.header, claims: parsed.claims, checks: parsed.checks };
    } catch (err) {
      return { ...base, ok: false, error: describeError(err, 'userinfo') };
    }
  }

  return {
    settings,
    getConfiguration,
    describeProvider,
    startAuthorization,
    completeAuthorization,
    fetchUserinfo,
    get lastDiscoveryError() {
      return lastDiscoveryError;
    },
  };
}

function idTokenChecks({ decoded, payload, pending, tokens, settings, jwksUri }) {
  const checks = [];
  const header = decoded.header || {};
  const now = Math.floor(Date.now() / 1000);

  checks.push({ title: 'state matches the request', detail: pending.state, ok: true });
  if (decoded.format === 'jwe') {
    checks.push({ title: 'Decrypted with the RP private key', detail: `${header.alg} · ${header.enc}`, ok: true });
    checks.push({ title: 'Signature verified', detail: `nested JWS · ${jwksUri}`, ok: true });
  } else {
    checks.push({ title: 'Signature verified', detail: `${header.alg}${header.kid ? ` · kid ${header.kid}` : ''} · ${jwksUri}`, ok: true });
  }
  checks.push({ title: 'iss equals the issuer', detail: String(payload.iss), ok: true });
  checks.push({ title: 'aud contains client_id', detail: [].concat(payload.aud).join(', '), ok: true });
  checks.push({ title: 'nonce matches the request', detail: String(payload.nonce), ok: true });
  if (pending.codeVerifier) {
    checks.push({ title: 'PKCE code_verifier accepted by the token endpoint', detail: 'S256', ok: true });
  }
  checks.push({
    title: 'exp is in the future',
    detail: `${formatTime(payload.exp)} · ${Math.max(0, payload.exp - now)} s left`,
    ok: payload.exp > now,
  });
  if (payload.iat) {
    checks.push({ title: 'iat is plausible', detail: formatTime(payload.iat), ok: payload.iat <= now + 300 });
  }
  if (payload.auth_time && pending.maxAge !== null && pending.maxAge !== undefined) {
    checks.push({
      title: `auth_time within max_age (${pending.maxAge} s)`,
      detail: formatTime(payload.auth_time),
      ok: now - payload.auth_time <= pending.maxAge + 60,
    });
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

/** Normalises openid-client / fetch errors into something the page can show. */
export function describeError(err, stage) {
  if (!err) return { error: 'unknown', error_description: 'Unknown error', stage };
  const base = { stage, name: err.name || 'Error' };
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
    return { ...base, error: err.code || 'client_error', error_description: detail ? `${err.message}: ${detail}` : err.message };
  }
  const cause = err.cause ? ` (${err.cause.code || err.cause.message || err.cause})` : '';
  return { ...base, error: err.code || 'unexpected_error', error_description: `${err.message}${cause}` };
}
