import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_SELECTION, ITSME_CLAIM_PREFIX,
  buildClaimsParameter, buildScopeList, buildStartRequest, requestedClaimKeys, shortClaimName, claimLabel,
} from '../public/js/catalog.js';
import { validateStartRequest, validateClaimsObject, ValidationError } from '../server/validate.js';

const BE_NN = ITSME_CLAIM_PREFIX + 'BENationalNumber';

test('default selection builds the claims parameter for both targets', () => {
  const claims = buildClaimsParameter(DEFAULT_SELECTION);
  assert.deepEqual(Object.keys(claims), ['userinfo', 'id_token']);
  assert.equal(claims.userinfo.name, null);
  assert.deepEqual(claims.userinfo.email, { essential: true });
  assert.deepEqual(claims.id_token[BE_NN], { essential: true });
  assert.equal(requestedClaimKeys(claims).length, 11);
});

test('target picks the member of the claims parameter', () => {
  const only = { ...DEFAULT_SELECTION, target: 'userinfo' };
  assert.deepEqual(Object.keys(buildClaimsParameter(only)), ['userinfo']);
  const none = { ...DEFAULT_SELECTION, claims: {} };
  assert.equal(buildClaimsParameter(none), null);
});

test('scope list keeps catalog order, inserts the service code and drops it when empty', () => {
  assert.deepEqual(buildScopeList(DEFAULT_SELECTION, 'MYSERVICE'), ['openid', 'service:MYSERVICE', 'profile', 'email', 'phone']);
  assert.deepEqual(buildScopeList(DEFAULT_SELECTION, ''), ['openid', 'profile', 'email', 'phone']);
  assert.deepEqual(buildScopeList({ ...DEFAULT_SELECTION, scopes: { address: true } }, ''), ['openid', 'address']);
});

test('start request only carries options that are set', () => {
  const body = buildStartRequest({ ...DEFAULT_SELECTION, acr: '', uiLocales: '', maxAge: '300', loginHint: ' ' }, 'X');
  assert.equal(body.acr_values, undefined);
  assert.equal(body.ui_locales, undefined);
  assert.equal(body.max_age, 300);
  assert.equal(body.login_hint, ' ');
  assert.equal(body.pkce, true);
});

test('display helpers shorten itsme URIs and label well-known claims', () => {
  assert.equal(shortClaimName(BE_NN), 'itsme:BENationalNumber');
  assert.equal(shortClaimName('email'), 'email');
  assert.equal(claimLabel(BE_NN), 'National number');
  assert.equal(claimLabel('something_custom'), 'something_custom');
});

test('server-side validation accepts what the page builds', () => {
  const body = buildStartRequest(DEFAULT_SELECTION, 'MYSERVICE');
  const out = validateStartRequest(body);
  assert.deepEqual(out.scopes, ['openid', 'service:MYSERVICE', 'profile', 'email', 'phone']);
  assert.deepEqual(out.claims, body.claims);
  assert.equal(out.options.acr_values, DEFAULT_SELECTION.acr);
  assert.equal(out.options.ui_locales, 'nl');
  assert.equal(out.pkce, true);
});

test('server-side validation rejects malformed claims and parameters', () => {
  assert.throws(() => validateStartRequest({ scopes: ['open id'] }), ValidationError);
  assert.throws(() => validateStartRequest({ scopes: ['openid'], claims: [] }), /claims must be a JSON object/);
  assert.throws(() => validateStartRequest({ scopes: ['openid'], claims: { id_token: { email: { bogus: 1 } } } }), /bogus/);
  assert.throws(() => validateStartRequest({ scopes: ['openid'], prompt: 'whatever' }), /unknown value/);
  assert.throws(() => validateStartRequest({ scopes: ['openid'], max_age: 'soon' }), /max_age/);

  const cleaned = validateClaimsObject({ userinfo: { email: { essential: true }, name: {} }, id_token: {} });
  assert.deepEqual(cleaned.errors, []);
  assert.deepEqual(cleaned.value, { userinfo: { email: { essential: true }, name: null } });
});

test('openid is always present in the scope list', () => {
  const out = validateStartRequest({ scopes: ['profile'] });
  assert.deepEqual(out.scopes, ['openid', 'profile']);
});
