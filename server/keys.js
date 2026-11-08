// Loads the relying party's private key (for private_key_jwt client
// authentication and for decrypting encrypted ID tokens / UserInfo responses)
// and derives the public JWKS the provider can fetch from /.well-known/jwks.json.
import fs from 'node:fs';
import path from 'node:path';
import { createPrivateKey, createPublicKey, webcrypto } from 'node:crypto';
import { calculateJwkThumbprint } from 'jose';

const SIGNING_ALGS = {
  RSA: { alg: 'RS256', params: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' } },
  'EC:P-256': { alg: 'ES256', params: { name: 'ECDSA', namedCurve: 'P-256' } },
  'EC:P-384': { alg: 'ES384', params: { name: 'ECDSA', namedCurve: 'P-384' } },
  'EC:P-521': { alg: 'ES512', params: { name: 'ECDSA', namedCurve: 'P-521' } },
};

function stripJwkMetadata(jwk) {
  const { alg, use, key_ops, kid, ...rest } = jwk;
  return rest;
}

function readKeyMaterial(settings) {
  if (settings.privateKey.jwk) return settings.privateKey.jwk.trim();
  if (settings.privateKey.file) return fs.readFileSync(path.resolve(settings.privateKey.file), 'utf8').trim();
  return null;
}

function toPrivateJwk(material) {
  if (material.startsWith('{')) {
    const parsed = JSON.parse(material);
    const jwk = parsed.keys ? parsed.keys.find((k) => k.d) : parsed;
    if (!jwk || !jwk.d) throw new Error('The JWK does not contain a private key (missing "d")');
    return jwk;
  }
  // PEM (PKCS#8 or PKCS#1) → JWK via node:crypto
  return createPrivateKey(material).export({ format: 'jwk' });
}

export async function loadRpKeys(settings) {
  const material = readKeyMaterial(settings);
  if (!material) return null;

  const privateJwk = toPrivateJwk(material);
  const bare = stripJwkMetadata(privateJwk);
  const kid = privateJwk.kid || (await calculateJwkThumbprint(bare));
  const family = bare.kty === 'EC' ? `EC:${bare.crv}` : bare.kty;
  const signing = SIGNING_ALGS[family];
  if (!signing) throw new Error(`Unsupported private key type ${family}; use an RSA or P-256/P-384/P-521 EC key`);

  const signingKey = await webcrypto.subtle.importKey('jwk', bare, signing.params, false, ['sign']);

  // The provider encrypts with the "enc" entry of our JWKS (kid "<kid>-enc"); the same RSA key
  // is imported once per OAEP variant so the JWE "alg" header picks the right one.
  const encKid = `${kid}-enc`;
  const decryption = [];
  if (bare.kty === 'RSA') {
    for (const [alg, hash] of [['RSA-OAEP', 'SHA-1'], ['RSA-OAEP-256', 'SHA-256']]) {
      decryption.push({
        alg,
        kid: encKid,
        key: await webcrypto.subtle.importKey('jwk', bare, { name: 'RSA-OAEP', hash }, false, ['decrypt']),
      });
    }
  }

  const publicJwk = createPublicKey(createPrivateKey({ key: bare, format: 'jwk' })).export({ format: 'jwk' });
  const publicJwks = {
    keys: [
      { ...publicJwk, kid, use: 'sig', alg: signing.alg },
      ...(bare.kty === 'RSA' ? [{ ...publicJwk, kid: encKid, use: 'enc', alg: 'RSA-OAEP' }] : []),
    ],
  };

  return {
    kid,
    alg: signing.alg,
    signing: { key: signingKey, kid },
    decryption,
    publicJwks,
  };
}
