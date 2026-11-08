// Validation of what the browser sends to POST /api/auth/start. The server
// never trusts the page: scopes, the claims object and the optional request
// parameters are checked here before anything reaches the provider.

const SCOPE_TOKEN = /^[\x21\x23-\x5B\x5D-\x7E]{1,128}$/; // RFC 6749 §3.3 scope-token
const PROMPT_VALUES = ['none', 'login', 'consent', 'select_account'];
const CLAIM_TARGETS = ['id_token', 'userinfo'];
const CLAIM_REQUEST_KEYS = ['essential', 'value', 'values'];
const MAX_CLAIMS_PER_TARGET = 80;

export class ValidationError extends Error {
  constructor(errors) {
    super(errors.join('; '));
    this.name = 'ValidationError';
    this.errors = errors;
  }
}

export function validateStartRequest(body) {
  const errors = [];
  const input = body && typeof body === 'object' ? body : {};

  // scopes
  let scopes = Array.isArray(input.scopes) ? input.scopes : [];
  scopes = scopes.map((s) => String(s).trim()).filter(Boolean);
  if (scopes.length > 30) errors.push('too many scopes (max 30)');
  for (const scope of scopes) {
    if (!SCOPE_TOKEN.test(scope)) errors.push(`invalid scope token "${scope}"`);
  }
  if (!scopes.includes('openid')) scopes.unshift('openid');
  scopes = [...new Set(scopes)];

  // claims parameter
  let claims = null;
  if (input.claims !== undefined && input.claims !== null) {
    const result = validateClaimsObject(input.claims);
    errors.push(...result.errors);
    claims = result.value;
  }

  // optional parameters
  const options = {};
  const acr = optionalString(input.acr_values, 'acr_values', 512, errors);
  if (acr) options.acr_values = acr;

  const prompt = optionalString(input.prompt, 'prompt', 64, errors);
  if (prompt) {
    const tokens = prompt.split(/\s+/);
    const bad = tokens.filter((t) => !PROMPT_VALUES.includes(t));
    if (bad.length) errors.push(`prompt contains unknown value(s): ${bad.join(', ')}`);
    if (tokens.includes('none') && tokens.length > 1) errors.push('prompt=none cannot be combined with other values');
    options.prompt = tokens.join(' ');
  }

  const uiLocales = optionalString(input.ui_locales, 'ui_locales', 100, errors);
  if (uiLocales) options.ui_locales = uiLocales;

  const loginHint = optionalString(input.login_hint, 'login_hint', 256, errors);
  if (loginHint) options.login_hint = loginHint;

  if (input.max_age !== undefined && input.max_age !== null && input.max_age !== '') {
    const n = Number(input.max_age);
    if (!Number.isInteger(n) || n < 0 || n > 31536000) errors.push('max_age must be an integer between 0 and 31536000');
    else options.max_age = n;
  }

  const pkce = input.pkce === undefined ? true : Boolean(input.pkce);

  if (errors.length) throw new ValidationError(errors);
  return { scopes, claims, options, pkce };
}

export function validateClaimsObject(raw) {
  const errors = [];
  if (!isPlainObject(raw)) {
    return { errors: ['claims must be a JSON object'], value: null };
  }
  const value = {};
  for (const [target, members] of Object.entries(raw)) {
    if (!CLAIM_TARGETS.includes(target)) {
      errors.push(`claims.${target} is not allowed (use id_token or userinfo)`);
      continue;
    }
    if (!isPlainObject(members)) {
      errors.push(`claims.${target} must be an object`);
      continue;
    }
    const entries = Object.entries(members);
    if (entries.length > MAX_CLAIMS_PER_TARGET) {
      errors.push(`claims.${target} has too many entries (max ${MAX_CLAIMS_PER_TARGET})`);
      continue;
    }
    const cleaned = {};
    for (const [name, request] of entries) {
      if (typeof name !== 'string' || name.length === 0 || name.length > 200) {
        errors.push(`claims.${target} has an invalid claim name`);
        continue;
      }
      if (request === null) {
        cleaned[name] = null;
        continue;
      }
      if (!isPlainObject(request)) {
        errors.push(`claims.${target}.${name} must be null or an object`);
        continue;
      }
      const spec = {};
      for (const [k, v] of Object.entries(request)) {
        if (!CLAIM_REQUEST_KEYS.includes(k)) {
          errors.push(`claims.${target}.${name}.${k} is not allowed`);
        } else if (k === 'essential' && typeof v !== 'boolean') {
          errors.push(`claims.${target}.${name}.essential must be boolean`);
        } else if (k === 'value' && !['string', 'number', 'boolean'].includes(typeof v)) {
          errors.push(`claims.${target}.${name}.value must be a string, number or boolean`);
        } else if (k === 'values' && !(Array.isArray(v) && v.every((x) => typeof x === 'string'))) {
          errors.push(`claims.${target}.${name}.values must be an array of strings`);
        } else {
          spec[k] = v;
        }
      }
      cleaned[name] = Object.keys(spec).length ? spec : null;
    }
    if (Object.keys(cleaned).length) value[target] = cleaned;
  }
  return { errors, value: Object.keys(value).length ? value : null };
}

function optionalString(value, name, max, errors) {
  if (value === undefined || value === null || value === '') return null;
  if (typeof value !== 'string') {
    errors.push(`${name} must be a string`);
    return null;
  }
  const trimmed = value.trim();
  if (trimmed.length > max) errors.push(`${name} is too long (max ${max})`);
  return trimmed || null;
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
