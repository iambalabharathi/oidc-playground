import { test } from 'node:test';
import assert from 'node:assert/strict';
import { bootStack, makeSession } from '../tools/stack-for-tests.js';

const BE_NN = 'http://itsme.services/v2/claim/BENationalNumber';

const selection = {
  scopes: ['openid', 'service:TESTSERVICE', 'profile', 'email', 'phone'],
  claims: {
    userinfo: { email: { essential: true }, gender: null, [BE_NN]: { essential: true } },
    id_token: { email: { essential: true }, gender: null, [BE_NN]: { essential: true } },
  },
  acr_values: 'http://itsme.services/v2/claim/acr_basic',
  ui_locales: 'nl',
  pkce: true,
};

async function runAuthorization(session, body = selection) {
  const start = await session.post('/api/auth/start', body);
  const startBody = await start.text();
  assert.equal(start.status, 200, startBody);
  const { url, params } = JSON.parse(startBody);

  // the browser would now be redirected to the provider; the mock auto-approves
  const atProvider = await fetch(url, { redirect: 'manual' });
  assert.equal(atProvider.status, 302);
  const callbackUrl = atProvider.headers.get('location');
  assert.ok(callbackUrl.includes('/callback?'), callbackUrl);

  const callback = await session.call(callbackUrl);
  assert.equal(callback.status, 302);
  assert.equal(callback.headers.get('location'), '/result');
  return { url, params, callbackUrl };
}

test('full authorization code flow against the mock provider', async (t) => {
  const stack = await bootStack();
  t.after(() => stack.close());
  const session = makeSession(stack.baseUrl);

  const config = await session.json('/api/config');
  assert.equal(config.discovery.ok, true, JSON.stringify(config.discovery));
  assert.equal(config.discovery.endpoints.userinfo_endpoint, `${stack.op.issuer}/userinfo`);
  assert.equal(config.provider.serviceCode, 'TESTSERVICE');

  const { params } = await runAuthorization(session);
  const byName = Object.fromEntries(params.map((p) => [p.k, p.v]));
  assert.equal(byName.response_type, 'code');
  assert.equal(byName.client_id, stack.op.clientId);
  assert.equal(byName.scope, 'openid service:TESTSERVICE profile email phone');
  assert.equal(byName.code_challenge_method, 'S256');
  assert.equal(byName.acr_values, 'http://itsme.services/v2/claim/acr_basic');
  assert.deepEqual(JSON.parse(byName.claims), selection.claims);

  const result = await session.json('/api/result');
  assert.equal(result.status, 'ok', JSON.stringify(result.error));
  assert.equal(String(result.tokens.token_type).toLowerCase(), 'bearer');
  assert.match(result.tokens.id_token, /^eyJ/);
  assert.equal(result.idToken.header.alg, 'RS256');
  assert.equal(result.idToken.payload.iss, stack.op.issuer);
  assert.equal(result.idToken.payload.email, 'lotte.vermeulen@example.com');
  assert.equal(result.idToken.payload[BE_NN], '91042312458');
  assert.equal(result.idToken.payload.gender, undefined, 'the mock omits gender on purpose');
  assert.equal(result.idToken.payload.acr, 'http://itsme.services/v2/claim/acr_basic');
  assert.ok(result.idToken.checks.length >= 7);
  assert.ok(result.idToken.checks.every((c) => c.ok), JSON.stringify(result.idToken.checks.filter((c) => !c.ok)));
  assert.equal(result.request.selection.pkce, true);

  const userinfo = await (await session.post('/api/userinfo')).json();
  assert.equal(userinfo.ok, true, JSON.stringify(userinfo.error));
  assert.equal(userinfo.format, 'json');
  assert.equal(userinfo.response.status, 200);
  assert.equal(userinfo.claims.sub, result.idToken.payload.sub);
  assert.equal(userinfo.claims.phone_number, '+32470123456');
  assert.equal(userinfo.claims.gender, undefined);
  assert.ok(userinfo.checks.every((c) => c.ok));

  const again = await session.json('/api/result');
  assert.equal(again.userinfo.format, 'json', 'userinfo result is kept in the session');

  const reset = await (await session.post('/api/reset')).json();
  assert.equal(reset.ok, true);
  assert.equal((await session.json('/api/result')).status, 'empty');
});

test('UserInfo returned as a signed JWT is verified and shown as claims', async (t) => {
  const stack = await bootStack({ mockOptions: { userinfoJwt: true } });
  t.after(() => stack.close());
  const session = makeSession(stack.baseUrl);
  await runAuthorization(session, { scopes: ['openid', 'profile', 'email'], pkce: false });

  const userinfo = await (await session.post('/api/userinfo')).json();
  assert.equal(userinfo.ok, true, JSON.stringify(userinfo.error));
  assert.equal(userinfo.format, 'jwt');
  assert.equal(userinfo.response.contentType.split(';')[0], 'application/jwt');
  assert.equal(userinfo.claims.given_name, 'Lotte');
  assert.ok(userinfo.checks.some((c) => c.title === 'Signature verified' && c.ok));
  assert.ok(userinfo.checks.some((c) => c.title === 'sub equals the ID token subject' && c.ok));
});

test('an access_denied callback is reported, not crashed on', async (t) => {
  const stack = await bootStack({ mockOptions: { autoApprove: false } });
  t.after(() => stack.close());
  const session = makeSession(stack.baseUrl);

  const start = await session.post('/api/auth/start', { scopes: ['openid'], pkce: true });
  const { url } = await start.json();
  const page = await fetch(url);
  const html = await page.text();
  const denyUrl = stack.op.issuer + html.match(/href="([^"]+)"\s*>Deny/)[1].replace(/&amp;/g, '&');

  const decision = await fetch(denyUrl, { redirect: 'manual' });
  assert.equal(decision.status, 302);
  const callback = await session.call(decision.headers.get('location'));
  assert.equal(callback.status, 302);
  const result = await session.json('/api/result');
  assert.equal(result.status, 'error');
  assert.equal(result.error.error, 'access_denied');
  assert.equal(result.error.stage, 'authorization');
});

test('a callback without a pending request explains itself', async (t) => {
  const stack = await bootStack();
  t.after(() => stack.close());
  const session = makeSession(stack.baseUrl);
  const res = await session.call('/callback?code=abc&state=xyz');
  assert.equal(res.status, 302);
  const result = await session.json('/api/result');
  assert.equal(result.status, 'error');
  assert.equal(result.error.error, 'no_pending_request');
});

test('a tampered state is rejected by the token exchange step', async (t) => {
  const stack = await bootStack();
  t.after(() => stack.close());
  const session = makeSession(stack.baseUrl);
  const { url } = await (await session.post('/api/auth/start', { scopes: ['openid'], pkce: true })).json();
  const atProvider = await fetch(url, { redirect: 'manual' });
  const callbackUrl = new URL(atProvider.headers.get('location'));
  callbackUrl.searchParams.set('state', 'not-the-state-we-sent');
  await session.call(callbackUrl.href);
  const result = await session.json('/api/result');
  assert.equal(result.status, 'error');
  assert.match(result.error.error_description, /state/i);
});

test('invalid start requests are rejected with details', async (t) => {
  const stack = await bootStack();
  t.after(() => stack.close());
  const session = makeSession(stack.baseUrl);
  const res = await session.post('/api/auth/start', { scopes: ['openid'], claims: { foo: {} }, prompt: 'none login', max_age: -1 });
  assert.equal(res.status, 400);
  const body = await res.json();
  assert.equal(body.error, 'invalid_request');
  assert.ok(body.errors.some((e) => e.includes('claims.foo')));
  assert.ok(body.errors.some((e) => e.includes('prompt=none')));
  assert.ok(body.errors.some((e) => e.includes('max_age')));
});
