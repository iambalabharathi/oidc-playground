import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_SELECTION, CUSTOM_CLAIM_ID_PREFIX,
  buildClaimsParameter, buildScopeList, buildStartRequest, buildAuthorizationParams, parseExtraParams, requestedClaimKeys, shortClaimName, claimLabel, allClaims, standardClaimByKey,
} from '../docs/js/catalog.js';

const EMPLOYEE_ID = 'https://example.com/claims/employee_id';
const withCustom = {
  ...DEFAULT_SELECTION,
  customClaims: [EMPLOYEE_ID],
  claims: { ...DEFAULT_SELECTION.claims, [CUSTOM_CLAIM_ID_PREFIX + EMPLOYEE_ID]: true },
  essential: { ...DEFAULT_SELECTION.essential, [CUSTOM_CLAIM_ID_PREFIX + EMPLOYEE_ID]: true },
};

test('default selection builds the claims parameter for both targets', () => {
  const claims = buildClaimsParameter(DEFAULT_SELECTION);
  assert.deepEqual(Object.keys(claims), ['userinfo', 'id_token']);
  assert.equal(claims.userinfo.name, null);
  assert.deepEqual(claims.userinfo.email, { essential: true });
  assert.equal(requestedClaimKeys(claims).length, 10);
});

test('custom claims are requested by their key, with their own essential flag', () => {
  const claims = buildClaimsParameter(withCustom);
  assert.deepEqual(claims.id_token[EMPLOYEE_ID], { essential: true });
  assert.deepEqual(claims.userinfo[EMPLOYEE_ID], { essential: true });
  assert.equal(requestedClaimKeys(claims).length, 11);
  assert.ok(allClaims(withCustom).some((c) => c.custom && c.key === EMPLOYEE_ID));
  assert.equal(allClaims(DEFAULT_SELECTION).filter((c) => c.custom).length, 0);
  assert.equal(standardClaimByKey('email').id, 'email');
  assert.equal(standardClaimByKey(EMPLOYEE_ID), undefined);
});

test('target picks the member of the claims parameter', () => {
  const only = { ...DEFAULT_SELECTION, target: 'userinfo' };
  assert.deepEqual(Object.keys(buildClaimsParameter(only)), ['userinfo']);
  const none = { ...DEFAULT_SELECTION, claims: {} };
  assert.equal(buildClaimsParameter(none), null);
});

test('scope list keeps catalog order and appends extra scopes as typed, without duplicates', () => {
  assert.deepEqual(buildScopeList(DEFAULT_SELECTION), ['openid', 'profile', 'email', 'phone']);
  assert.deepEqual(buildScopeList({ ...DEFAULT_SELECTION, extraScopes: ' groups,  email api:read ' }), ['openid', 'profile', 'email', 'phone', 'groups', 'api:read']);
  assert.deepEqual(buildScopeList({ ...DEFAULT_SELECTION, scopes: { address: true } }), ['openid', 'address']);
});

test('start request only carries options that are set', () => {
  const body = buildStartRequest({ ...DEFAULT_SELECTION, acr: '', uiLocales: '', maxAge: '300', loginHint: ' ' });
  assert.equal(body.acr_values, undefined);
  assert.equal(body.ui_locales, undefined);
  assert.equal(body.max_age, 300);
  assert.equal(body.login_hint, ' ');
  assert.equal(body.pkce, true);
  assert.equal(buildStartRequest({ ...DEFAULT_SELECTION, acr: 'urn:example:acr:strong' }).acr_values, 'urn:example:acr:strong');
});

test('display helpers shorten URI claim keys and label well-known claims', () => {
  assert.equal(shortClaimName(EMPLOYEE_ID), '…/employee_id');
  assert.equal(shortClaimName('email'), 'email');
  assert.equal(claimLabel('email'), 'E-mail');
  assert.equal(claimLabel(EMPLOYEE_ID), '…/employee_id');
  assert.equal(claimLabel('something_custom'), 'something_custom');
});

test('the page only builds the request unless an exchange mode is picked', () => {
  assert.equal(DEFAULT_SELECTION.mode, 'request');
  assert.equal(DEFAULT_SELECTION.modeChosen, false);
});

test('extra parameters are read one per line or &-separated, last one wins', () => {
  assert.deepEqual(parseExtraParams(''), []);
  assert.deepEqual(parseExtraParams(' display = popup \n# a comment\n\nresponse_mode=form_post&flag'), [['display', 'popup'], ['response_mode', 'form_post'], ['flag', '']]);
  assert.deepEqual(parseExtraParams('a=1\na=2'), [['a', '2']]);
  assert.deepEqual(parseExtraParams('target=https://x.example/?a=b'), [['target', 'https://x.example/?a=b']]);
});

test('extra parameters are appended, or replace a built-in parameter in place', () => {
  const ctx = { clientId: 'c', redirectUri: 'https://app.example/cb', state: 's', nonce: 'n', codeChallenge: 'ch' };
  const plain = buildAuthorizationParams(buildStartRequest({ ...DEFAULT_SELECTION, claims: {} }), ctx);
  assert.deepEqual(plain.map(([k]) => k), ['response_type', 'client_id', 'redirect_uri', 'scope', 'state', 'nonce', 'code_challenge', 'code_challenge_method']);

  const body = buildStartRequest({ ...DEFAULT_SELECTION, claims: {}, extraParams: 'display=popup\nresponse_type=code id_token\nstate=fixed' });
  const params = buildAuthorizationParams(body, ctx);
  assert.deepEqual(params.map(([k]) => k), [...plain.map(([k]) => k), 'display']);
  const byKey = Object.fromEntries(params);
  assert.equal(byKey.response_type, 'code id_token');
  assert.equal(byKey.state, 'fixed');
  assert.equal(byKey.display, 'popup');
});
