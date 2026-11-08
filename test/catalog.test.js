import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_SELECTION, ITSME_CLAIM_PREFIX,
  buildClaimsParameter, buildScopeList, buildStartRequest, requestedClaimKeys, shortClaimName, claimLabel,
} from '../public/js/catalog.js';

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
