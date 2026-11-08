// Turns a private JWK pasted into the page into the CryptoKeys openid-client
// needs: one to sign private_key_jwt client assertions, and (for RSA keys) the
// RSA-OAEP variants that decrypt encrypted ID tokens / UserInfo responses.
// The public half is derived so the page can show what the hosted JWKS must contain.
import { createPrivateKey, createPublicKey, webcrypto } from 'node:crypto';
import { calculateJwkThumbprint } from 'jose';

const SIGNING_ALGS = {
  RSA: { alg: 'RS256', params: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' } },
  'EC:P-256': { alg: 'ES256', params: { name: 'ECDSA', namedCurve: 'P-256' } },
  'EC:P-384': { alg: 'ES384', params: { name: 'ECDSA', namedCurve: 'P-384' } },
  'EC:P-521': { alg: 'ES512', params: { name: 'ECDSA', namedCurve: 'P-521' } },
};

export class KeyError extends Error {}

function stripJwkMetadata(jwk) {
  const { alg, use, key_ops, kid, x5c, x5t, 'x5t#S256': x5tS256, x5u, ...rest } = jwk;
  return rest;
}

/** Accepts a JWK object, a JWK JSON string, a JWKS with one private key, or a PEM private key. */
export function parsePrivateKeyMaterial(material) {
  if (material && typeof material === 'object') {
    const jwk = material.keys ? material.keys.find((k) => k.d) : material;
    if (!jwk || !jwk.d) throw new KeyError('The JWK does not contain a private key (no "d" member)');
    return jwk;
  }
  const text = String(material || '').trim();
  if (!text) throw new KeyError('No private key provided');
  if (text.startsWith('{')) {
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new KeyError('The private key is not valid JSON');
    }
    return parsePrivateKeyMaterial(parsed);
  }
  if (text.includes('-----BEGIN')) {
    try {
      return createPrivateKey(text).export({ format: 'jwk' });
    } catch (err) {
      throw new KeyError(`The PEM private key could not be read: ${err.message}`);
    }
  }
  throw new KeyError('Paste the private key as a JWK (JSON) or as PEM');
}

export async function importPrivateKey(material) {
  const privateJwk = parsePrivateKeyMaterial(material);
  const bare = stripJwkMetadata(privateJwk);
  const family = bare.kty === 'EC' ? `EC:${bare.crv}` : bare.kty;
  const signing = SIGNING_ALGS[family];
  if (!signing) throw new KeyError(`Unsupported key type ${family}; use an RSA or P-256/P-384/P-521 EC key`);

  let kid;
  try {
    kid = privateJwk.kid || (await calculateJwkThumbprint(bare));
  } catch (err) {
    throw new KeyError(`Invalid JWK: ${err.message}`);
  }

  let signingKey;
  try {
    signingKey = await webcrypto.subtle.importKey('jwk', bare, signing.params, false, ['sign']);
  } catch (err) {
    throw new KeyError(`The private key could not be imported: ${err.message}`);
  }

  const decryption = [];
  if (bare.kty === 'RSA') {
    for (const [alg, hash] of [['RSA-OAEP', 'SHA-1'], ['RSA-OAEP-256', 'SHA-256']]) {
      decryption.push({
        alg,
        key: await webcrypto.subtle.importKey('jwk', bare, { name: 'RSA-OAEP', hash }, false, ['decrypt']),
      });
    }
  }

  const publicJwk = createPublicKey(createPrivateKey({ key: bare, format: 'jwk' })).export({ format: 'jwk' });

  return {
    kid,
    alg: privateJwk.alg || signing.alg,
    kty: bare.kty,
    signing: { key: signingKey, kid },
    decryption,
    publicJwk: { ...publicJwk, kid, use: privateJwk.use || 'sig', alg: privateJwk.alg || signing.alg },
  };
}
