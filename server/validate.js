// Validation of what the page sends. The server trusts nothing from the browser:
// every URL, identifier and credential is checked before it is used.

const CLIENT_AUTH_METHODS = ['client_secret_post', 'client_secret_basic', 'private_key_jwt', 'none'];

export class ValidationError extends Error {
  constructor(errors) {
    super(errors.join('; '));
    this.name = 'ValidationError';
    this.errors = errors;
  }
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function str(value, name, { max = 2048, required = false } = {}, errors) {
  if (value === undefined || value === null || value === '') {
    if (required) errors.push(`${name} is required`);
    return null;
  }
  if (typeof value !== 'string') {
    errors.push(`${name} must be a string`);
    return null;
  }
  const trimmed = value.trim();
  if (!trimmed && required) errors.push(`${name} is required`);
  if (trimmed.length > max) errors.push(`${name} is too long (max ${max} characters)`);
  return trimmed || null;
}

export function normalizeIssuer(value, errors, name = 'issuer') {
  const text = str(value, name, { max: 2048, required: true }, errors);
  if (!text) return null;
  let url;
  try {
    url = new URL(text);
  } catch {
    errors.push(`${name} must be an absolute URL`);
    return null;
  }
  if (!['http:', 'https:'].includes(url.protocol)) errors.push(`${name} must use http or https`);
  if (url.search || url.hash) errors.push(`${name} must not contain a query string or fragment`);
  if (url.username || url.password) errors.push(`${name} must not contain credentials`);
  return url.href.replace(/\/+$/, '');
}

export function validateClientAuth(value, errors) {
  const input = isPlainObject(value) ? value : { method: value };
  const method = str(input.method, 'client_auth.method', { max: 64 }, errors) || 'none';
  if (!CLIENT_AUTH_METHODS.includes(method)) {
    errors.push(`client_auth.method must be one of ${CLIENT_AUTH_METHODS.join(', ')}`);
    return null;
  }
  const out = { method };
  if (method.startsWith('client_secret')) {
    out.client_secret = str(input.client_secret, 'client_auth.client_secret', { max: 4096, required: true }, errors);
  }
  if (input.private_key !== undefined && input.private_key !== null && input.private_key !== '') {
    if (typeof input.private_key === 'string') {
      if (input.private_key.length > 32768) errors.push('client_auth.private_key is too long');
      out.private_key = input.private_key;
    } else if (isPlainObject(input.private_key)) {
      out.private_key = input.private_key;
    } else {
      errors.push('client_auth.private_key must be a JWK object, a JWK/JWKS JSON string or PEM');
    }
  }
  if (method === 'private_key_jwt' && !out.private_key) {
    errors.push('client_auth.method=private_key_jwt needs client_auth.private_key');
  }
  return out;
}

export function validateDiscoverRequest(body) {
  const errors = [];
  const issuer = normalizeIssuer(body?.issuer, errors);
  if (errors.length) throw new ValidationError(errors);
  return { issuer };
}

export function validateTokenRequest(body) {
  const errors = [];
  const input = isPlainObject(body) ? body : {};
  const issuer = normalizeIssuer(input.issuer, errors);
  const clientId = str(input.client_id, 'client_id', { max: 512, required: true }, errors);
  const clientAuth = validateClientAuth(input.client_auth, errors);

  const callbackUrl = str(input.callback_url, 'callback_url', { max: 16384, required: true }, errors);
  if (callbackUrl) {
    try {
      const u = new URL(callbackUrl);
      if (!['http:', 'https:'].includes(u.protocol)) errors.push('callback_url must be http(s)');
    } catch {
      errors.push('callback_url must be an absolute URL (the page URL the provider redirected to)');
    }
  }
  const expectedState = str(input.expected_state, 'expected_state', { max: 512, required: true }, errors);
  const expectedNonce = str(input.expected_nonce, 'expected_nonce', { max: 512 }, errors);
  const codeVerifier = str(input.code_verifier, 'code_verifier', { max: 256 }, errors);
  if (codeVerifier && !/^[A-Za-z0-9._~-]{43,128}$/.test(codeVerifier)) errors.push('code_verifier is not a valid PKCE verifier');

  let maxAge = null;
  if (input.max_age !== undefined && input.max_age !== null && input.max_age !== '') {
    const n = Number(input.max_age);
    if (!Number.isInteger(n) || n < 0 || n > 31536000) errors.push('max_age must be an integer between 0 and 31536000');
    else maxAge = n;
  }

  if (errors.length) throw new ValidationError(errors);
  return { issuer, clientId, clientAuth, callbackUrl, expectedState, expectedNonce: expectedNonce || undefined, codeVerifier, maxAge };
}

export function validateUserinfoRequest(body) {
  const errors = [];
  const input = isPlainObject(body) ? body : {};
  const issuer = normalizeIssuer(input.issuer, errors);
  const clientId = str(input.client_id, 'client_id', { max: 512 }, errors);
  const accessToken = str(input.access_token, 'access_token', { max: 16384, required: true }, errors);
  const expectedSub = str(input.expected_sub, 'expected_sub', { max: 1024 }, errors);
  let privateKeyMaterial = null;
  if (input.private_key !== undefined && input.private_key !== null && input.private_key !== '') {
    if (typeof input.private_key === 'string' || isPlainObject(input.private_key)) privateKeyMaterial = input.private_key;
    else errors.push('private_key must be a JWK object, a JWK/JWKS JSON string or PEM');
  }
  if (errors.length) throw new ValidationError(errors);
  return { issuer, clientId, accessToken, expectedSub, privateKeyMaterial };
}

export function validateInspectKeyRequest(body) {
  const errors = [];
  const input = isPlainObject(body) ? body : {};
  if (input.private_key === undefined || input.private_key === null || input.private_key === '') errors.push('private_key is required');
  else if (typeof input.private_key !== 'string' && !isPlainObject(input.private_key)) errors.push('private_key must be a JWK object, a JWK/JWKS JSON string or PEM');
  else if (typeof input.private_key === 'string' && input.private_key.length > 32768) errors.push('private_key is too long');
  if (errors.length) throw new ValidationError(errors);
  return { privateKey: input.private_key };
}
