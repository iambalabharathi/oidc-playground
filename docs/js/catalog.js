// What can be requested: standard scopes and claims from OpenID Connect Core
// §5.1/§5.4, plus any provider-specific scopes and claims typed in by the user.
// Pure data + pure functions, so the same module is unit-tested in Node.

export const SCOPES = [
  { id: 'openid', locked: true, hint: 'Required for an ID token' },
  { id: 'profile', hint: 'name, given_name, family_name, birthdate, gender, locale, picture, …' },
  { id: 'email', hint: 'email, email_verified' },
  { id: 'phone', hint: 'phone_number, phone_number_verified' },
  { id: 'address', hint: 'address (JSON object)' },
  { id: 'offline_access', hint: 'Ask for a refresh token' },
];

const std = (names) => names.map((n) => ({ id: n, key: n, label: n, title: n }));

export const CLAIM_GROUPS = [
  {
    id: 'profile',
    title: 'Profile',
    hint: 'scope: profile',
    claims: std(['name', 'given_name', 'family_name', 'middle_name', 'nickname', 'preferred_username', 'profile', 'picture', 'website', 'gender', 'birthdate', 'zoneinfo', 'locale', 'updated_at']),
  },
  { id: 'email', title: 'Email', hint: 'scope: email', claims: std(['email', 'email_verified']) },
  { id: 'phone', title: 'Phone', hint: 'scope: phone', claims: std(['phone_number', 'phone_number_verified']) },
  {
    id: 'address',
    title: 'Address',
    hint: 'scope: address · JSON object (formatted, street_address, locality, region, postal_code, country)',
    claims: std(['address']),
  },
];

export const STANDARD_CLAIMS = CLAIM_GROUPS.flatMap((g) => g.claims);
const STANDARD_BY_KEY = new Map(STANDARD_CLAIMS.map((c) => [c.key, c]));

export const CUSTOM_CLAIM_ID_PREFIX = 'custom:';

/** A picker entry for a provider-specific claim (any name or URI). */
export function customClaim(key) {
  return { id: CUSTOM_CLAIM_ID_PREFIX + key, key, label: shortClaimName(key), title: key, custom: true };
}

/** Every claim the picker can show for this selection: the standard ones plus the custom ones added by the user. */
export function allClaims(selection) {
  return [...STANDARD_CLAIMS, ...(selection.customClaims || []).map(customClaim)];
}

/** Standard claim with this key, if there is one (lets "email" typed as a custom claim toggle the standard row). */
export function standardClaimByKey(key) {
  return STANDARD_BY_KEY.get(key);
}

/** Known issuers offered as presets ({ id, label, issuer, keyUrl? }); empty, so the issuer is typed in. */
export const ISSUER_PRESETS = [];

export const CLIENT_AUTH_METHODS = [
  { id: 'private_key_jwt', label: 'private_key_jwt · signed client assertion (JWK)' },
  { id: 'client_secret_post', label: 'client_secret_post · secret in the token request body' },
  { id: 'client_secret_basic', label: 'client_secret_basic · HTTP Basic on the token endpoint' },
  { id: 'none', label: 'none · public client (PKCE only)' },
];

/** Who the private_key_jwt client assertion is addressed to (its `aud` claim); providers differ. */
export const ASSERTION_AUDIENCES = [
  { id: 'token_endpoint', label: 'token endpoint URL · OpenID Connect Core §9' },
  { id: 'issuer', label: 'issuer identifier · RFC 7523bis' },
];

export const DEFAULT_SELECTION = {
  issuer: '',
  clientId: '',
  clientAuthMethod: 'private_key_jwt',
  assertionAudience: 'token_endpoint', // aud of the client assertion: token_endpoint | issuer
  redirectUri: '', // empty = this page; set when the client is registered with another redirect URI (the callback URL is then pasted back)
  keyUrl: '', // where the private key (JWK, private JWKS or PEM) is fetched from; the key itself stays in sessionStorage
  mode: 'request', // request (only build and open the request) | direct (exchange in the browser) | helper (exchange through a helper)
  modeChosen: false, // true once the user picked the mode themselves
  helperUrl: 'http://localhost:3000',
  scopes: { profile: true, email: true, phone: true },
  extraScopes: '', // provider-specific scopes, space-separated, sent as typed
  customClaims: [], // provider-specific claim names or URIs, requested through the claims parameter
  claims: {
    name: true, given_name: true, family_name: true, birthdate: true, gender: true, locale: true,
    email: true, email_verified: true, phone_number: true, phone_number_verified: true,
  },
  essential: { email: true },
  target: 'both', // userinfo | id_token | both
  acr: '',
  prompt: '',
  uiLocales: '',
  maxAge: '',
  loginHint: '',
  extraParams: '', // any other request parameters, one key=value per line; they override a built-in parameter of the same name
  pkce: true,
};

/** Builds the OIDC `claims` request parameter from the picker state. */
export function buildClaimsParameter(selection) {
  const selected = allClaims(selection).filter((c) => selection.claims[c.id]);
  if (!selected.length) return null;
  const entry = (c) => (selection.essential[c.id] ? { essential: true } : null);
  const out = {};
  if (selection.target === 'userinfo' || selection.target === 'both') {
    out.userinfo = Object.fromEntries(selected.map((c) => [c.key, entry(c)]));
  }
  if (selection.target === 'id_token' || selection.target === 'both') {
    out.id_token = Object.fromEntries(selected.map((c) => [c.key, entry(c)]));
  }
  return out;
}

/** Splits free-text scopes ("a b, c") into unique tokens. */
export function parseExtraScopes(text) {
  return [...new Set(String(text || '').split(/[\s,]+/).filter(Boolean))];
}

/** The scope list that goes on the wire: catalog order first, then the extra scopes as typed. */
export function buildScopeList(selection) {
  const list = SCOPES.filter((s) => s.locked || selection.scopes[s.id]).map((s) => s.id);
  for (const s of parseExtraScopes(selection.extraScopes)) if (!list.includes(s)) list.push(s);
  return list;
}

/**
 * Free-text request parameters: one key=value per line (or separated by &), values as they
 * should arrive at the provider (not URL-encoded). A later line with the same key wins.
 */
export function parseExtraParams(text) {
  const out = new Map();
  for (const part of String(text || '').split(/[\n&]+/)) {
    const line = part.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    const key = (eq === -1 ? line : line.slice(0, eq)).trim();
    if (!key) continue;
    out.set(key, eq === -1 ? '' : line.slice(eq + 1).trim());
  }
  return [...out];
}

/** Everything the authorization request needs, before state/nonce/PKCE are generated. */
export function buildStartRequest(selection) {
  const body = {
    scopes: buildScopeList(selection),
    claims: buildClaimsParameter(selection),
    pkce: !!selection.pkce,
  };
  if (selection.acr) body.acr_values = selection.acr;
  if (selection.prompt) body.prompt = selection.prompt;
  if (selection.uiLocales) body.ui_locales = selection.uiLocales;
  if (selection.maxAge !== '' && selection.maxAge !== null && selection.maxAge !== undefined) body.max_age = Number(selection.maxAge);
  if (selection.loginHint) body.login_hint = selection.loginHint;
  const extra = parseExtraParams(selection.extraParams);
  if (extra.length) body.extra = extra;
  return body;
}

/** Ordered authorization request parameters, exactly as they go on the wire. */
export function buildAuthorizationParams(body, { clientId, redirectUri, state, nonce, codeChallenge }) {
  const params = [
    ['response_type', 'code'],
    ['client_id', clientId],
    ['redirect_uri', redirectUri],
    ['scope', body.scopes.join(' ')],
    ['state', state],
    ['nonce', nonce],
  ];
  if (body.pkce && codeChallenge) params.push(['code_challenge', codeChallenge], ['code_challenge_method', 'S256']);
  for (const k of ['acr_values', 'prompt', 'ui_locales', 'max_age', 'login_hint']) {
    if (body[k] !== undefined && body[k] !== null && body[k] !== '') params.push([k, String(body[k])]);
  }
  if (body.claims) params.push(['claims', JSON.stringify(body.claims)]);
  // Extra parameters go last; one that names a built-in parameter replaces its value in place.
  for (const [k, v] of body.extra || []) {
    const existing = params.find((p) => p[0] === k);
    if (existing) existing[1] = v;
    else params.push([k, v]);
  }
  return params;
}

/** The names of all individually requested claims (keys as sent to the provider). */
export function requestedClaimKeys(claimsParameter) {
  const keys = new Set();
  for (const target of ['id_token', 'userinfo']) {
    for (const k of Object.keys(claimsParameter?.[target] || {})) keys.add(k);
  }
  return [...keys];
}

/** Short display name for a claim key: URI-style keys are shown by their last path segment. */
export function shortClaimName(key) {
  if (!key.includes('/')) return key;
  const last = key.replace(/\/+$/, '').split('/').pop();
  return last ? `…/${last}` : key;
}

/** Human label for well-known claims; falls back to the short name. */
const LABELS = {
  sub: 'Subject',
  name: 'Full name',
  given_name: 'First name',
  family_name: 'Last name',
  middle_name: 'Middle name',
  nickname: 'Nickname',
  preferred_username: 'Username',
  profile: 'Profile URL',
  picture: 'Picture URL',
  website: 'Website',
  gender: 'Gender',
  birthdate: 'Birthdate',
  zoneinfo: 'Time zone',
  locale: 'Locale',
  updated_at: 'Updated at',
  email: 'E-mail',
  email_verified: 'E-mail verified',
  phone_number: 'Phone',
  phone_number_verified: 'Phone verified',
  address: 'Address',
};

export function claimLabel(key) {
  return LABELS[key] || shortClaimName(key);
}

/** Claims about the token itself (shown separately from claims about the user). */
export const TOKEN_CLAIMS = ['iss', 'sub', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'acr', 'amr', 'azp', 'at_hash', 'c_hash', 'sid', 'jti', 'nbf'];
