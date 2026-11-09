// The same code the page runs in the browser, exercised in Node against the mock provider.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as jose from 'jose';
import { direct } from '../docs/js/backends.js';
import { startMockOp } from '../tools/mock-op.js';
import { hostJwks, startFlow, authorizeAtMock } from '../tools/stack-for-tests.js';

const REDIRECT_URI = 'http://localhost:3000/';
const BE_NN = 'http://itsme.services/v2/claim/BENationalNumber';

async function boot(mockOptions = {}) {
  const op = await startMockOp({ port: 0, autoApprove: true, quiet: true, ...mockOptions });
  return op;
}

async function run(op, { clientAuth, pkce = true, scopes = ['openid', 'profile', 'email'], claims = { userinfo: { email: null, [BE_NN]: null }, id_token: { email: null } } }) {
  const discovered = await direct.discover(op.issuer);
  assert.equal(discovered.ok, true, JSON.stringify(discovered.error));
  const flow = startFlow({ authorizationEndpoint: discovered.provider.endpoints.authorization_endpoint, clientId: op.clientId, redirectUri: REDIRECT_URI, scopes, claims, pkce });
  const callbackUrl = await authorizeAtMock(flow);
  const result = await direct.token({
    issuer: op.issuer,
    client_id: op.clientId,
    client_auth: clientAuth,
    callback_url: callbackUrl,
    redirect_uri: REDIRECT_URI,
    expected_state: flow.state,
    expected_nonce: flow.nonce,
    code_verifier: flow.codeVerifier,
  });
  return { discovered, flow, callbackUrl, result };
}

test('browser client: discover → token → userinfo with client_secret_post', async (t) => {
  const op = await boot();
  t.after(() => op.close());
  const { discovered, result } = await run(op, { clientAuth: { method: 'client_secret_post', client_secret: op.clientSecret } });

  assert.equal(discovered.provider.endpoints.userinfo_endpoint, `${op.issuer}/userinfo`);
  assert.equal(result.ok, true, JSON.stringify(result.error));
  assert.equal(result.idToken.header.alg, 'RS256');
  assert.equal(result.idToken.payload.email, 'lotte.vermeulen@example.com');
  assert.equal(result.idToken.payload.gender, undefined);
  assert.ok(result.idToken.checks.every((c) => c.ok), JSON.stringify(result.idToken.checks.filter((c) => !c.ok)));
  assert.ok(result.idToken.checks.some((c) => c.title.startsWith('at_hash')));
  assert.equal(result.raw.status, 200);

  const ui = await direct.userinfo({ issuer: op.issuer, client_id: op.clientId, access_token: result.tokens.access_token, expected_sub: result.idToken.payload.sub });
  assert.equal(ui.ok, true, JSON.stringify(ui.error));
  assert.equal(ui.userinfo.ok, true, JSON.stringify(ui.userinfo.error));
  assert.equal(ui.userinfo.format, 'json');
  assert.equal(ui.userinfo.claims[BE_NN], '91042312458');
  assert.equal(ui.userinfo.claims.sub, result.idToken.payload.sub);
});

test('browser client: client_secret_basic, no PKCE, signed-JWT userinfo', async (t) => {
  const op = await boot({ userinfoJwt: true });
  t.after(() => op.close());
  const { result } = await run(op, { clientAuth: { method: 'client_secret_basic', client_secret: op.clientSecret }, pkce: false });
  assert.equal(result.ok, true, JSON.stringify(result.error));
  assert.ok(!result.idToken.checks.some((c) => c.title.startsWith('PKCE')));

  const ui = await direct.userinfo({ issuer: op.issuer, client_id: op.clientId, access_token: result.tokens.access_token, expected_sub: result.idToken.payload.sub });
  assert.equal(ui.userinfo.ok, true, JSON.stringify(ui.userinfo.error));
  assert.equal(ui.userinfo.format, 'jwt');
  assert.ok(ui.userinfo.checks.some((c) => c.title === 'Signature verified' && c.ok));
  assert.equal(ui.userinfo.claims.given_name, 'Lotte');
});

test('browser client: private_key_jwt with a hosted JWKS, plus encrypted responses', async (t) => {
  const { privateKey, publicKey } = await jose.generateKeyPair('RS256', { extractable: true });
  const privateJwk = { ...(await jose.exportJWK(privateKey)), kid: 'browser-key', alg: 'RS256' };
  const hosted = await hostJwks({ keys: [{ ...(await jose.exportJWK(publicKey)), kid: 'browser-key', alg: 'RS256', use: 'sig' }] });
  const op = await boot({ encryptIdToken: true, encryptUserinfo: true, clientJwksUri: hosted.url });
  t.after(async () => {
    await op.close();
    await hosted.close();
  });

  const inspected = await direct.inspectKey(JSON.stringify(privateJwk));
  assert.equal(inspected.ok, true, JSON.stringify(inspected.error));
  assert.equal(inspected.key.kid, 'browser-key');
  assert.equal(inspected.key.public_jwk.n, privateJwk.n);
  assert.ok(!inspected.key.public_jwk.d);

  const { result } = await run(op, { clientAuth: { method: 'private_key_jwt', private_key: JSON.stringify(privateJwk) } });
  assert.equal(result.ok, true, JSON.stringify(result.error));
  assert.equal(result.idToken.format, 'jwe');
  assert.equal(result.idToken.header.alg, 'RSA-OAEP');
  assert.equal(result.idToken.payload.given_name, 'Lotte');
  assert.ok(result.idToken.checks.some((c) => c.title.startsWith('Decrypted') && c.ok));

  const ui = await direct.userinfo({ issuer: op.issuer, client_id: op.clientId, access_token: result.tokens.access_token, expected_sub: result.idToken.payload.sub, private_key: JSON.stringify(privateJwk) });
  assert.equal(ui.userinfo.ok, true, JSON.stringify(ui.userinfo.error));
  assert.equal(ui.userinfo.format, 'jwe');
  assert.equal(ui.userinfo.claims.email, 'lotte.vermeulen@example.com');
});

test('browser client: PEM private key is accepted', async (t) => {
  const { privateKey, publicKey } = await jose.generateKeyPair('RS256', { extractable: true });
  const pem = await jose.exportPKCS8(privateKey);
  const publicJwk = { ...(await jose.exportJWK(publicKey)), alg: 'RS256', use: 'sig' };
  publicJwk.kid = await jose.calculateJwkThumbprint(publicJwk);
  const hosted = await hostJwks({ keys: [publicJwk] });
  const op = await boot({ clientJwksUri: hosted.url });
  t.after(async () => {
    await op.close();
    await hosted.close();
  });
  const inspected = await direct.inspectKey(pem);
  assert.equal(inspected.ok, true, JSON.stringify(inspected.error));
  assert.equal(inspected.key.kid, publicJwk.kid);
  const { result } = await run(op, { clientAuth: { method: 'private_key_jwt', private_key: pem } });
  assert.equal(result.ok, true, JSON.stringify(result.error));
});

test('browser client: errors are reported, not thrown', async (t) => {
  const op = await boot();
  t.after(() => op.close());

  const wrongSecret = await run(op, { clientAuth: { method: 'client_secret_post', client_secret: 'nope' } });
  assert.equal(wrongSecret.result.ok, false);
  assert.equal(wrongSecret.result.error.error, 'invalid_client');

  const discovered = await direct.discover(op.issuer);
  const flow = startFlow({ authorizationEndpoint: discovered.provider.endpoints.authorization_endpoint, clientId: op.clientId, redirectUri: REDIRECT_URI });
  const callbackUrl = new URL(await authorizeAtMock(flow));
  callbackUrl.searchParams.set('state', 'tampered');
  const tampered = await direct.token({
    issuer: op.issuer, client_id: op.clientId, client_auth: { method: 'client_secret_post', client_secret: op.clientSecret },
    callback_url: callbackUrl.href, redirect_uri: REDIRECT_URI, expected_state: flow.state, expected_nonce: flow.nonce, code_verifier: flow.codeVerifier,
  });
  assert.equal(tampered.ok, false);
  assert.match(tampered.error.error_description, /state/i);

  const denied = await direct.token({
    issuer: op.issuer, client_id: op.clientId, client_auth: { method: 'client_secret_post', client_secret: op.clientSecret },
    callback_url: `${REDIRECT_URI}?error=access_denied&error_description=nope&state=${flow.state}`, redirect_uri: REDIRECT_URI, expected_state: flow.state, expected_nonce: flow.nonce,
  });
  assert.equal(denied.ok, false);
  assert.equal(denied.error.error, 'access_denied');
  assert.equal(denied.error.stage, 'authorization');

  const unreachable = await direct.discover('http://127.0.0.1:9');
  assert.equal(unreachable.ok, false);
  assert.equal(unreachable.error.error, 'network_error');

  const insecure = await direct.discover('http://example.com');
  assert.equal(insecure.ok, false);
  assert.equal(insecure.error.error, 'insecure_issuer');

  const badKey = await direct.inspectKey('not a key');
  assert.equal(badKey.ok, false);
  assert.equal(badKey.error.error, 'invalid_private_key');
});
