// Key parsing, as done in the browser (docs/js/oidc-client.js) and in the helper (server/keys.js):
// a single JWK, a private JWKS with separate signing and encryption keys, PEM, and a public-only JWKS.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as jose from 'jose';
import { parsePrivateKey, inspectKey } from '../docs/js/oidc-client.js';
import { importPrivateKey } from '../server/keys.js';

async function rsa(kid, use, alg) {
  const { privateKey, publicKey } = await jose.generateKeyPair(alg, { extractable: true });
  return {
    priv: { ...(await jose.exportJWK(privateKey)), kid, use, alg },
    pub: { ...(await jose.exportJWK(publicKey)), kid, use, alg },
    privateKey,
  };
}

test('a private JWKS with sig and enc keys: both parsers sign with sig and decrypt with enc', async () => {
  const sig = await rsa('rp-sig', 'sig', 'RS256');
  const enc = await rsa('rp-enc', 'enc', 'RSA-OAEP');
  const material = JSON.stringify({ keys: [enc.priv, sig.priv, sig.pub] }); // order and a stray public key must not matter

  const browser = await parsePrivateKey(material);
  assert.equal(browser.kid, 'rp-sig');
  assert.equal(browser.alg, 'RS256');
  assert.deepEqual(browser.decryptionKids, ['rp-enc']);
  assert.deepEqual(browser.keysFound, { private: 2, public: 1 });
  assert.equal(browser.publicJwk.n, sig.pub.n);
  assert.ok(!browser.publicJwk.d);
  assert.equal(browser.decryptionKeys.length, 2, 'RSA-OAEP and RSA-OAEP-256 variants of the enc key');

  const inspected = await inspectKey(material);
  assert.deepEqual(inspected.decryption_kids, ['rp-enc']);
  assert.equal(inspected.public_jwk.kid, 'rp-sig');

  const helper = await importPrivateKey(material);
  assert.equal(helper.kid, 'rp-sig');
  assert.deepEqual(helper.decryptionKids, ['rp-enc']);
  assert.deepEqual(helper.keysFound, { private: 2, public: 1 });
  assert.equal(helper.publicJwk.n, sig.pub.n);
  assert.deepEqual(helper.decryption.map((k) => k.alg), ['RSA-OAEP', 'RSA-OAEP-256']);
});

test('a single RSA JWK signs and decrypts; its kid defaults to the thumbprint', async () => {
  const { privateKey, publicKey } = await jose.generateKeyPair('RS256', { extractable: true });
  const priv = await jose.exportJWK(privateKey);
  const thumbprint = await jose.calculateJwkThumbprint(await jose.exportJWK(publicKey));

  const browser = await parsePrivateKey(priv);
  assert.equal(browser.kid, thumbprint);
  assert.deepEqual(browser.decryptionKids, [thumbprint]);
  const helper = await importPrivateKey(JSON.stringify(priv));
  assert.equal(helper.kid, thumbprint);
  assert.deepEqual(helper.decryptionKids, [thumbprint]);
});

test('PEM (PKCS#8) is accepted by both parsers with the same kid', async () => {
  const { privateKey, publicKey } = await jose.generateKeyPair('RS256', { extractable: true });
  const pem = await jose.exportPKCS8(privateKey);
  const thumbprint = await jose.calculateJwkThumbprint(await jose.exportJWK(publicKey));
  assert.equal((await parsePrivateKey(pem)).kid, thumbprint);
  assert.equal((await importPrivateKey(pem)).kid, thumbprint);
});

test('EC keys sign with ES256 and have nothing to decrypt with', async () => {
  const { privateKey } = await jose.generateKeyPair('ES256', { extractable: true });
  const priv = { ...(await jose.exportJWK(privateKey)), kid: 'ec' };
  const browser = await parsePrivateKey(priv);
  assert.equal(browser.alg, 'ES256');
  assert.deepEqual(browser.decryptionKids, []);
  const helper = await importPrivateKey(priv);
  assert.equal(helper.alg, 'ES256');
  assert.deepEqual(helper.decryption, []);
});

test('a public-only JWKS and garbage are refused with readable messages', async () => {
  const sig = await rsa('rp-sig', 'sig', 'RS256');
  const publicOnly = JSON.stringify({ keys: [sig.pub] });
  await assert.rejects(parsePrivateKey(publicOnly), /No private key found/);
  await assert.rejects(importPrivateKey(publicOnly), /No private key found/);
  await assert.rejects(parsePrivateKey('{"kty":"RSA","n":"abc"}'), /private key/i);
  await assert.rejects(importPrivateKey('not a key'), /JWK|PEM/);
  await assert.rejects(parsePrivateKey('{not json'), /not valid JSON/);
});
