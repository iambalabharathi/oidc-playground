import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import * as jose from 'jose';
import { bootStack, makeSession } from '../tools/stack-for-tests.js';

async function writeTempJwk() {
  const { privateKey } = await jose.generateKeyPair('RS256', { extractable: true });
  const jwk = { ...(await jose.exportJWK(privateKey)), kid: 'rp-test-key' };
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'oidc-pg-')), 'rp.jwk.json');
  fs.writeFileSync(file, JSON.stringify(jwk));
  return file;
}

async function authorize(session) {
  const start = await session.post('/api/auth/start', { scopes: ['openid', 'profile', 'email'], claims: { userinfo: { email: null }, id_token: { email: null } }, pkce: true });
  const { url } = JSON.parse(await start.text());
  const atProvider = await fetch(url, { redirect: 'manual' });
  const callback = await session.call(atProvider.headers.get('location'));
  assert.equal(callback.status, 302);
  return session.json('/api/result');
}

test('private_key_jwt client authentication with the JWKS served by the app', async (t) => {
  const keyFile = await writeTempJwk();
  const stack = await bootStack({ env: { CLIENT_AUTH: 'private_key_jwt', CLIENT_SECRET: '', PRIVATE_KEY_FILE: keyFile } });
  t.after(() => stack.close());
  stack.op.setClientJwksUri(`${stack.baseUrl}/.well-known/jwks.json`);
  const session = makeSession(stack.baseUrl);

  const jwks = await session.json('/.well-known/jwks.json');
  assert.equal(jwks.keys[0].kid, 'rp-test-key');
  assert.equal(jwks.keys[0].use, 'sig');
  assert.equal(jwks.keys[1].use, 'enc');
  assert.ok(!jwks.keys.some((k) => k.d), 'private material must never be published');

  const config = await session.json('/api/config');
  assert.equal(config.provider.clientAuth, 'private_key_jwt');
  assert.equal(config.provider.jwksUrl, `${stack.baseUrl}/.well-known/jwks.json`);

  const result = await authorize(session);
  assert.equal(result.status, 'ok', JSON.stringify(result.error));
  assert.equal(result.idToken.payload.email, 'lotte.vermeulen@example.com');
});

test('encrypted (JWE) ID token and UserInfo are decrypted with the RP key', async (t) => {
  const keyFile = await writeTempJwk();
  const stack = await bootStack({
    env: { CLIENT_AUTH: 'private_key_jwt', CLIENT_SECRET: '', PRIVATE_KEY_FILE: keyFile, DECRYPT_RESPONSES: '1' },
    mockOptions: { encryptIdToken: true, encryptUserinfo: true },
  });
  t.after(() => stack.close());
  stack.op.setClientJwksUri(`${stack.baseUrl}/.well-known/jwks.json`);
  const session = makeSession(stack.baseUrl);

  const result = await authorize(session);
  assert.equal(result.status, 'ok', JSON.stringify(result.error));
  assert.equal(result.tokens.id_token.split('.').length, 5, 'the raw token stays a JWE');
  assert.equal(result.idToken.format, 'jwe');
  assert.equal(result.idToken.header.alg, 'RSA-OAEP');
  assert.equal(result.idToken.header.enc, 'A128CBC-HS256');
  assert.equal(result.idToken.payload.given_name, 'Lotte');
  assert.ok(result.idToken.checks.some((c) => c.title.startsWith('Decrypted') && c.ok));
  assert.ok(result.idToken.checks.every((c) => c.ok), JSON.stringify(result.idToken.checks.filter((c) => !c.ok)));

  const userinfo = await (await session.post('/api/userinfo')).json();
  assert.equal(userinfo.ok, true, JSON.stringify(userinfo.error));
  assert.equal(userinfo.format, 'jwe');
  assert.equal(userinfo.claims.email, 'lotte.vermeulen@example.com');
  assert.ok(userinfo.checks.some((c) => c.title.startsWith('Decrypted') && c.ok));
  assert.ok(userinfo.checks.some((c) => c.title === 'Signature verified' && c.ok));
  assert.ok(userinfo.checks.some((c) => c.title === 'sub equals the ID token subject' && c.ok));
});

test('an encrypted response without a configured key is reported clearly', async (t) => {
  const keyFile = await writeTempJwk();
  // the mock encrypts with the key the app publishes, but the app is not told to decrypt
  const stack = await bootStack({
    env: { CLIENT_AUTH: 'private_key_jwt', CLIENT_SECRET: '', PRIVATE_KEY_FILE: keyFile },
    mockOptions: { encryptIdToken: true },
  });
  t.after(() => stack.close());
  stack.op.setClientJwksUri(`${stack.baseUrl}/.well-known/jwks.json`);
  const session = makeSession(stack.baseUrl);

  const result = await authorize(session);
  assert.equal(result.status, 'error');
  assert.equal(result.error.stage, 'token');
  assert.ok(result.error.error_description.length > 0);
});
