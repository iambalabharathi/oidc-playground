import { test } from 'node:test';
import assert from 'node:assert/strict';
import { bootStack, makeApi, startFlow, authorizeAtMock } from '../tools/stack-for-tests.js';

const BE_NN = 'http://itsme.services/v2/claim/BENationalNumber';
const CLAIMS = {
  userinfo: { email: { essential: true }, gender: null, [BE_NN]: { essential: true } },
  id_token: { email: { essential: true }, gender: null, [BE_NN]: { essential: true } },
};

function clientAuthFor(stack) {
  return { method: 'client_secret_post', client_secret: stack.op.clientSecret };
}

test('full authorization code flow: discover → authorize → token → userinfo', async (t) => {
  const stack = await bootStack();
  t.after(() => stack.close());
  const api = makeApi(stack.baseUrl);

  const discovered = await api.post('/api/discover', { issuer: stack.op.issuer });
  assert.equal(discovered.ok, true, JSON.stringify(discovered.error));
  assert.equal(discovered.provider.endpoints.userinfo_endpoint, `${stack.op.issuer}/userinfo`);
  assert.ok(discovered.provider.claims_parameter_supported);

  const flow = startFlow({
    authorizationEndpoint: discovered.provider.endpoints.authorization_endpoint,
    clientId: stack.op.clientId,
    redirectUri: stack.redirectUri,
    scopes: ['openid', 'service:TESTSERVICE', 'profile', 'email', 'phone'],
    claims: CLAIMS,
    extra: { acr_values: 'http://itsme.services/v2/claim/acr_basic', ui_locales: 'nl' },
  });
  const callbackUrl = await authorizeAtMock(flow);
  assert.ok(callbackUrl.startsWith(`${stack.redirectUri}?`), callbackUrl);

  const result = await api.post('/api/token', {
    issuer: stack.op.issuer,
    client_id: stack.op.clientId,
    client_auth: clientAuthFor(stack),
    callback_url: callbackUrl,
    expected_state: flow.state,
    expected_nonce: flow.nonce,
    code_verifier: flow.codeVerifier,
  });
  assert.equal(result.ok, true, JSON.stringify(result.error));
  assert.equal(String(result.tokens.token_type).toLowerCase(), 'bearer');
  assert.match(result.tokens.id_token, /^eyJ/);
  assert.equal(result.idToken.header.alg, 'RS256');
  assert.equal(result.idToken.payload.iss, stack.op.issuer);
  assert.equal(result.idToken.payload.nonce, flow.nonce);
  assert.equal(result.idToken.payload.email, 'lotte.vermeulen@example.com');
  assert.equal(result.idToken.payload[BE_NN], '91042312458');
  assert.equal(result.idToken.payload.gender, undefined, 'the mock omits gender on purpose');
  assert.equal(result.idToken.payload.acr, 'http://itsme.services/v2/claim/acr_basic');
  assert.ok(result.idToken.checks.length >= 7);
  assert.ok(result.idToken.checks.every((c) => c.ok), JSON.stringify(result.idToken.checks.filter((c) => !c.ok)));
  assert.equal(result.endpoints.userinfo_endpoint, `${stack.op.issuer}/userinfo`);

  const ui = await api.post('/api/userinfo', {
    issuer: stack.op.issuer,
    client_id: stack.op.clientId,
    access_token: result.tokens.access_token,
    expected_sub: result.idToken.payload.sub,
  });
  assert.equal(ui.ok, true, JSON.stringify(ui.error));
  assert.equal(ui.userinfo.ok, true, JSON.stringify(ui.userinfo.error));
  assert.equal(ui.userinfo.format, 'json');
  assert.equal(ui.userinfo.response.status, 200);
  assert.equal(ui.userinfo.claims.sub, result.idToken.payload.sub);
  assert.equal(ui.userinfo.claims.phone_number, '+32470123456');
  assert.equal(ui.userinfo.claims.gender, undefined);
  assert.ok(ui.userinfo.checks.every((c) => c.ok));
});

test('UserInfo returned as a signed JWT is verified and shown as claims', async (t) => {
  const stack = await bootStack({ mockOptions: { userinfoJwt: true } });
  t.after(() => stack.close());
  const api = makeApi(stack.baseUrl);
  const { provider } = await api.post('/api/discover', { issuer: stack.op.issuer });
  const flow = startFlow({ authorizationEndpoint: provider.endpoints.authorization_endpoint, clientId: stack.op.clientId, redirectUri: stack.redirectUri, scopes: ['openid', 'profile', 'email'], pkce: false });
  const callbackUrl = await authorizeAtMock(flow);
  const result = await api.post('/api/token', {
    issuer: stack.op.issuer, client_id: stack.op.clientId, client_auth: clientAuthFor(stack),
    callback_url: callbackUrl, expected_state: flow.state, expected_nonce: flow.nonce,
  });
  assert.equal(result.ok, true, JSON.stringify(result.error));

  const { userinfo } = await api.post('/api/userinfo', {
    issuer: stack.op.issuer, client_id: stack.op.clientId, access_token: result.tokens.access_token, expected_sub: result.idToken.payload.sub,
  });
  assert.equal(userinfo.ok, true, JSON.stringify(userinfo.error));
  assert.equal(userinfo.format, 'jwt');
  assert.equal(userinfo.response.contentType.split(';')[0], 'application/jwt');
  assert.equal(userinfo.claims.given_name, 'Lotte');
  assert.ok(userinfo.checks.some((c) => c.title === 'Signature verified' && c.ok));
  assert.ok(userinfo.checks.some((c) => c.title === 'sub equals the ID token subject' && c.ok));
});

test('client_secret_basic works too', async (t) => {
  const stack = await bootStack();
  t.after(() => stack.close());
  const api = makeApi(stack.baseUrl);
  const { provider } = await api.post('/api/discover', { issuer: stack.op.issuer });
  const flow = startFlow({ authorizationEndpoint: provider.endpoints.authorization_endpoint, clientId: stack.op.clientId, redirectUri: stack.redirectUri });
  const callbackUrl = await authorizeAtMock(flow);
  const result = await api.post('/api/token', {
    issuer: stack.op.issuer, client_id: stack.op.clientId, client_auth: { method: 'client_secret_basic', client_secret: stack.op.clientSecret },
    callback_url: callbackUrl, expected_state: flow.state, expected_nonce: flow.nonce, code_verifier: flow.codeVerifier,
  });
  assert.equal(result.ok, true, JSON.stringify(result.error));
});

test('a wrong client secret is reported as invalid_client', async (t) => {
  const stack = await bootStack();
  t.after(() => stack.close());
  const api = makeApi(stack.baseUrl);
  const { provider } = await api.post('/api/discover', { issuer: stack.op.issuer });
  const flow = startFlow({ authorizationEndpoint: provider.endpoints.authorization_endpoint, clientId: stack.op.clientId, redirectUri: stack.redirectUri });
  const callbackUrl = await authorizeAtMock(flow);
  const result = await api.post('/api/token', {
    issuer: stack.op.issuer, client_id: stack.op.clientId, client_auth: { method: 'client_secret_post', client_secret: 'nope' },
    callback_url: callbackUrl, expected_state: flow.state, expected_nonce: flow.nonce, code_verifier: flow.codeVerifier,
  });
  assert.equal(result.ok, false);
  assert.equal(result.error.error, 'invalid_client');
  assert.equal(result.error.status, 401);
});

test('an access_denied callback is reported, not crashed on', async (t) => {
  const stack = await bootStack({ mockOptions: { autoApprove: false } });
  t.after(() => stack.close());
  const api = makeApi(stack.baseUrl);
  const { provider } = await api.post('/api/discover', { issuer: stack.op.issuer });
  const flow = startFlow({ authorizationEndpoint: provider.endpoints.authorization_endpoint, clientId: stack.op.clientId, redirectUri: stack.redirectUri });

  const consent = await fetch(flow.url);
  const html = await consent.text();
  const denyUrl = stack.op.issuer + html.match(/href="([^"]+)"\s*>Deny/)[1].replace(/&amp;/g, '&');
  const decision = await fetch(denyUrl, { redirect: 'manual' });
  const callbackUrl = decision.headers.get('location');
  assert.match(callbackUrl, /error=access_denied/);

  const result = await api.post('/api/token', {
    issuer: stack.op.issuer, client_id: stack.op.clientId, client_auth: clientAuthFor(stack),
    callback_url: callbackUrl, expected_state: flow.state, expected_nonce: flow.nonce, code_verifier: flow.codeVerifier,
  });
  assert.equal(result.ok, false);
  assert.equal(result.error.error, 'access_denied');
  assert.equal(result.error.stage, 'authorization');
});

test('a tampered state is rejected', async (t) => {
  const stack = await bootStack();
  t.after(() => stack.close());
  const api = makeApi(stack.baseUrl);
  const { provider } = await api.post('/api/discover', { issuer: stack.op.issuer });
  const flow = startFlow({ authorizationEndpoint: provider.endpoints.authorization_endpoint, clientId: stack.op.clientId, redirectUri: stack.redirectUri });
  const callbackUrl = new URL(await authorizeAtMock(flow));
  callbackUrl.searchParams.set('state', 'not-the-state-we-sent');
  const result = await api.post('/api/token', {
    issuer: stack.op.issuer, client_id: stack.op.clientId, client_auth: clientAuthFor(stack),
    callback_url: callbackUrl.href, expected_state: flow.state, expected_nonce: flow.nonce, code_verifier: flow.codeVerifier,
  });
  assert.equal(result.ok, false);
  assert.match(result.error.error_description, /state/i);
});

test('invalid requests are rejected with details', async (t) => {
  const stack = await bootStack();
  t.after(() => stack.close());
  const api = makeApi(stack.baseUrl);

  const bad = await api.post('/api/token', { issuer: 'ftp://x', client_auth: { method: 'private_key_jwt' }, callback_url: 'nope', code_verifier: 'short' });
  assert.equal(bad.status, 400);
  assert.equal(bad.error.error, 'invalid_request');
  for (const needle of ['issuer', 'client_id', 'private_key', 'callback_url', 'expected_state', 'code_verifier']) {
    assert.ok(bad.error.errors.some((e) => e.includes(needle)), `expected an error about ${needle}: ${bad.error.errors.join(' | ')}`);
  }

  const insecure = await api.post('/api/discover', { issuer: 'http://example.com' });
  assert.equal(insecure.ok, false);
  assert.match(insecure.error.error_description, /localhost/);

  const unknown = await api.post('/api/discover', { issuer: 'http://127.0.0.1:9' });
  assert.equal(unknown.ok, false);
  assert.equal(unknown.error.stage, 'discovery');
});
