// What can be requested: standard scopes and claims from OpenID Connect Core
// §5.1/§5.4, plus the itsme®-specific claims (requested by their full URI).
// Pure data + pure functions, so the same module is unit-tested in Node.

export const ITSME_CLAIM_PREFIX = 'http://itsme.services/v2/claim/';

export const SCOPES = [
  { id: 'openid', locked: true, hint: 'Required for an ID token' },
  { id: 'service', dynamic: true, hint: 'itsme® service code' },
  { id: 'profile', hint: 'name, given_name, family_name, birthdate, gender, locale, picture, …' },
  { id: 'email', hint: 'email, email_verified' },
  { id: 'phone', hint: 'phone_number, phone_number_verified' },
  { id: 'address', hint: 'address (JSON object)' },
  { id: 'eid', hint: 'itsme®: BENationalNumber, BEeidSn' },
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
  {
    id: 'itsme',
    title: 'itsme® claims',
    hint: `requested by full URI · ${ITSME_CLAIM_PREFIX}…`,
    claims: [
      ['be_nn', 'BENationalNumber'],
      ['be_eid_sn', 'BEeidSn'],
      ['pob', 'place_of_birth'],
      ['citizenship', 'claim_citizenship'],
      ['citizenship_iso', 'claim_citizenship_as_iso'],
      ['device', 'claim_device'],
      ['doc_type', 'IDDocumentType'],
      ['doc_sn', 'IDDocumentSN'],
      ['validity_to', 'validityTo'],
      ['photo', 'physical_person_photo'],
    ].map(([id, name]) => ({ id, key: ITSME_CLAIM_PREFIX + name, label: name, title: ITSME_CLAIM_PREFIX + name })),
  },
];

export const ALL_CLAIMS = CLAIM_GROUPS.flatMap((g) => g.claims);
const CLAIM_BY_ID = new Map(ALL_CLAIMS.map((c) => [c.id, c]));

export const ACR_PRESETS = [
  { value: '', label: 'provider default' },
  { value: `${ITSME_CLAIM_PREFIX}acr_basic`, label: 'acr_basic · PIN or biometrics' },
  { value: `${ITSME_CLAIM_PREFIX}acr_advanced`, label: 'acr_advanced · PIN only' },
];

export const DEFAULT_SELECTION = {
  scopes: { service: true, profile: true, email: true, phone: true },
  claims: {
    name: true, given_name: true, family_name: true, birthdate: true, gender: true, locale: true,
    email: true, email_verified: true, phone_number: true, phone_number_verified: true, be_nn: true,
  },
  essential: { email: true, be_nn: true },
  target: 'both', // userinfo | id_token | both
  acr: `${ITSME_CLAIM_PREFIX}acr_basic`,
  prompt: '',
  uiLocales: 'nl',
  maxAge: '',
  loginHint: '',
  pkce: true,
};

/** Builds the OIDC `claims` request parameter from the picker state. */
export function buildClaimsParameter(selection) {
  const selected = ALL_CLAIMS.filter((c) => selection.claims[c.id]);
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

/** The scope list that goes on the wire, in catalog order. */
export function buildScopeList(selection, serviceCode) {
  return SCOPES.filter((s) => s.locked || selection.scopes[s.id])
    .map((s) => (s.dynamic ? `service:${serviceCode || 'SERVICE_CODE'}` : s.id))
    .filter((s) => !(s.startsWith('service:') && !serviceCode));
}

/** Everything POST /api/auth/start needs. */
export function buildStartRequest(selection, serviceCode) {
  const body = {
    scopes: buildScopeList(selection, serviceCode),
    claims: buildClaimsParameter(selection),
    pkce: !!selection.pkce,
  };
  if (selection.acr) body.acr_values = selection.acr;
  if (selection.prompt) body.prompt = selection.prompt;
  if (selection.uiLocales) body.ui_locales = selection.uiLocales;
  if (selection.maxAge !== '' && selection.maxAge !== null && selection.maxAge !== undefined) body.max_age = Number(selection.maxAge);
  if (selection.loginHint) body.login_hint = selection.loginHint;
  return body;
}

/** The names of all individually requested claims (keys as sent to the provider). */
export function requestedClaimKeys(claimsParameter) {
  const keys = new Set();
  for (const target of ['id_token', 'userinfo']) {
    for (const k of Object.keys(claimsParameter?.[target] || {})) keys.add(k);
  }
  return [...keys];
}

export function claimById(id) {
  return CLAIM_BY_ID.get(id);
}

/** Short display name for a claim key (strips the itsme URI prefix). */
export function shortClaimName(key) {
  return key.startsWith(ITSME_CLAIM_PREFIX) ? `itsme:${key.slice(ITSME_CLAIM_PREFIX.length)}` : key;
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
  [ITSME_CLAIM_PREFIX + 'BENationalNumber']: 'National number',
  [ITSME_CLAIM_PREFIX + 'BEeidSn']: 'eID card number',
  [ITSME_CLAIM_PREFIX + 'place_of_birth']: 'Place of birth',
  [ITSME_CLAIM_PREFIX + 'claim_citizenship']: 'Citizenship',
  [ITSME_CLAIM_PREFIX + 'claim_citizenship_as_iso']: 'Citizenship (ISO)',
  [ITSME_CLAIM_PREFIX + 'claim_device']: 'Device',
  [ITSME_CLAIM_PREFIX + 'IDDocumentType']: 'ID document type',
  [ITSME_CLAIM_PREFIX + 'IDDocumentSN']: 'ID document number',
  [ITSME_CLAIM_PREFIX + 'validityTo']: 'Document valid until',
  [ITSME_CLAIM_PREFIX + 'physical_person_photo']: 'Photo',
};

export function claimLabel(key) {
  return LABELS[key] || shortClaimName(key);
}

/** Claims about the token itself (shown separately from claims about the user). */
export const TOKEN_CLAIMS = ['iss', 'sub', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'acr', 'amr', 'azp', 'at_hash', 'c_hash', 'sid', 'jti', 'nbf'];
