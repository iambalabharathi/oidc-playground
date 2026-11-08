import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as jose from 'jose';
import { bootStack, makeApi, hostJwks, startFlow, authorizeAtMock } from '../tools/stack-for-tests.js';

/** An RSA key pair: the private JWK is what the user pastes, the public JWKS is what they host on a public link. */
async function makeKeys(kid = 'rp-test-key') {
  const { privateKey, publicKey } = await jose.generateKeyPair('RS256', { extractable: true });
  const privateJwk = { ...(await jose.exportJWK(privateKey)), kid, alg: 'RS256' };
  const publicJwk = { ...(await jose.exportJWK(publicKey)), kid, alg: 'RS256', use: 'sig' };
  return { privateJwk, jwks: { keys: [publicJwk] } };
}

async function runFlow(stack, api, clientAuth, { pkce = true } = {}) {
  const { provider } = await api.post('/api/discover', { issuer: stack.op.issuer });
  const flow = startFlow({
    authorizationEndpoint: provider.endpoints.authorization_endpoint,
    clientId: stack.op.clientId,
    redirectUri: stack.redirectUri,
    scopes: ['openid', 'profile', 'email'],
    claims: { userinfo: { email: null }, id_token: { email: null } },
    pkce,
  });
  const callbackUrl = await authorizeAtMock(flow);
  return api.post('/api/token', {
    issuer: stack.op.issuer,
    client_id: stack.op.clientId,
    client_auth: clientAuth,
    callback_url: callbackUrl,
    expected_state: flow.state,
    expected_nonce: flow.nonce,
    code_verifier: flow.codeVerifier,
  });
}

test('private_key_jwt with the public JWKS hosted on an external link', async (t) => {
  const { privateJwk, jwks } = await makeKeys();
  const hosted = await hostJwks(jwks);
  const stack = await bootStack();
  t.after(async () => {
    await stack.close();
    await hosted.close();
  });
  stack.op.setClientJwksUri(hosted.url);
  const api = makeApi(stack.baseUrl);

  const inspected = await api.post('/api/keys/inspect', { private_key: JSON.stringify(privateJwk) });
  assert.equal(inspected.ok, true, JSON.stringify(inspected.error));
  assert.equal(inspected.key.kid, 'rp-test-key');
  assert.equal(inspected.key.alg, 'RS256');
  assert.equal(inspected.key.public_jwk.n, jwks.keys[0].n, 'the derived public key matches what is hosted');
  assert.ok(!inspected.key.public_jwk.d);

  const result = await runFlow(stack, api, { method: 'private_key_jwt', private_key: JSON.stringify(privateJwk) });
  assert.equal(result.ok, true, JSON.stringify(result.error));
  assert.equal(result.idToken.payload.email, 'lotte.vermeulen@example.com');
});

test('a private key as PEM is accepted as well', async (t) => {
  const { privateKey, publicKey } = await jose.generateKeyPair('RS256', { extractable: true });
  const pem = await jose.exportPKCS8(privateKey);
  const publicJwk = { ...(await jose.exportJWK(publicKey)), alg: 'RS256', use: 'sig' };
  publicJwk.kid = await jose.calculateJwkThumbprint(publicJwk); // same thumbprint the server derives for a kid-less key
  const hosted = await hostJwks({ keys: [publicJwk] });
  const stack = await bootStack();
  t.after(async () => {
    await stack.close();
    await hosted.close();
  });
  stack.op.setClientJwksUri(hosted.url);
  const api = makeApi(stack.baseUrl);

  const inspected = await api.post('/api/keys/inspect', { private_key: pem });
  assert.equal(inspected.key.kid, publicJwk.kid);

  const result = await runFlow(stack, api, { method: 'private_key_jwt', private_key: pem });
  assert.equal(result.ok, true, JSON.stringify(result.error));
});

test('encrypted (JWE) ID token and UserInfo are decrypted with the pasted private key', async (t) => {
  const { privateJwk, jwks } = await makeKeys('rp-enc-key');
  jwks.keys[0].use = 'enc';
  jwks.keys[0].alg = 'RSA-OAEP';
  const hosted = await hostJwks(jwks);
  const stack = await bootStack({ mockOptions: { encryptIdToken: true, encryptUserinfo: true } });
  t.after(async () => {
    await stack.close();
    await hosted.close();
  });
  stack.op.setClientJwksUri(hosted.url);
  const api = makeApi(stack.baseUrl);

  // client_secret_post for authentication, the pasted key only for decryption
  const result = await runFlow(stack, api, { method: 'client_secret_post', client_secret: stack.op.clientSecret, private_key: privateJwk });
  assert.equal(result.ok, true, JSON.stringify(result.error));
  assert.equal(result.tokens.id_token.split('.').length, 5, 'the raw token stays a JWE');
  assert.equal(result.idToken.format, 'jwe');
  assert.equal(result.idToken.header.alg, 'RSA-OAEP');
  assert.equal(result.idToken.header.kid, 'rp-enc-key');
  assert.equal(result.idToken.payload.given_name, 'Lotte');
  assert.ok(result.idToken.checks.some((c) => c.title.startsWith('Decrypted') && c.ok));
  assert.ok(result.idToken.checks.every((c) => c.ok), JSON.stringify(result.idToken.checks.filter((c) => !c.ok)));

  const { userinfo } = await api.post('/api/userinfo', {
    issuer: stack.op.issuer,
    client_id: stack.op.clientId,
    access_token: result.tokens.access_token,
    expected_sub: result.idToken.payload.sub,
    private_key: privateJwk,
  });
  assert.equal(userinfo.ok, true, JSON.stringify(userinfo.error));
  assert.equal(userinfo.format, 'jwe');
  assert.equal(userinfo.claims.email, 'lotte.vermeulen@example.com');
  assert.ok(userinfo.checks.some((c) => c.title.startsWith('Decrypted') && c.ok));
  assert.ok(userinfo.checks.some((c) => c.title === 'Signature verified' && c.ok));
});

test('an encrypted ID token without a key is explained', async (t) => {
  const { jwks } = await makeKeys('rp-enc-key');
  const hosted = await hostJwks(jwks);
  const stack = await bootStack({ mockOptions: { encryptIdToken: true } });
  t.after(async () => {
    await stack.close();
    await hosted.close();
  });
  stack.op.setClientJwksUri(hosted.url);
  const api = makeApi(stack.baseUrl);

  const result = await runFlow(stack, api, { method: 'client_secret_post', client_secret: stack.op.clientSecret });
  assert.equal(result.ok, false);
  assert.equal(result.error.stage, 'token');
  assert.ok(result.error.error_description.length > 0);
});

test('a garbage private key is rejected with a readable message', async (t) => {
  const stack = await bootStack();
  t.after(() => stack.close());
  const api = makeApi(stack.baseUrl);
  const inspected = await api.post('/api/keys/inspect', { private_key: '{"kty":"RSA","n":"abc"}' });
  assert.equal(inspected.ok, false);
  assert.equal(inspected.error.error, 'invalid_private_key');
  assert.match(inspected.error.error_description, /private key/i);
});
