// Turns the private key material the page sends (a JWK, a JWKS with private keys,
// or PEM) into the CryptoKeys openid-client needs: one to sign private_key_jwt
// client assertions, and the RSA-OAEP variants that decrypt encrypted ID tokens /
// UserInfo responses. A JWKS may hold a separate "sig" and "enc" key.
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

const isEncAlg = (alg) => typeof alg === 'string' && alg.startsWith('RSA-OAEP');

function stripJwkMetadata(jwk) {
  const { alg, use, key_ops, kid, x5c, x5t, 'x5t#S256': x5tS256, x5u, ...rest } = jwk;
  return rest;
}

/** Parses the material into a JWK or JWKS object (PEM becomes a single private JWK). */
export function parsePrivateKeyMaterial(material) {
  if (material && typeof material === 'object') return material;
  const text = String(material || '').trim();
  if (!text) throw new KeyError('No private key provided');
  if (text.startsWith('{')) {
    try {
      return JSON.parse(text);
    } catch {
      throw new KeyError('The private key is not valid JSON');
    }
  }
  if (text.includes('-----BEGIN')) {
    try {
      return createPrivateKey(text).export({ format: 'jwk' });
    } catch (err) {
      throw new KeyError(`The PEM private key could not be read: ${err.message}`);
    }
  }
  throw new KeyError('Provide the private key as a JWK / JWKS (JSON) or as PEM');
}

/** Picks the signing key and the decrypting RSA keys out of a JWK or JWKS; public keys are ignored. */
export function selectPrivateJwks(parsed) {
  const keys = (parsed && Array.isArray(parsed.keys) ? parsed.keys : [parsed]).filter((k) => k && typeof k === 'object');
  const priv = keys.filter((k) => k.d);
  const signing = priv.find((k) => k.use === 'sig')
    || priv.find((k) => !k.use && !isEncAlg(k.alg))
    || priv.find((k) => !isEncAlg(k.alg))
    || priv[0];
  let decryption = priv.filter((k) => k.kty === 'RSA' && (k.use === 'enc' || isEncAlg(k.alg)));
  if (!decryption.length && signing?.kty === 'RSA') decryption = [signing];
  if (!signing || !signing.d) {
    throw new KeyError(keys.length && !priv.length
      ? 'No private key found: the JWKS only holds public keys (no "d" member) — send the private JWKS, not the published one'
      : 'The JWK does not contain a private key (no "d" member)');
  }
  return { signing, decryption, privateCount: priv.length, publicCount: keys.length - priv.length };
}

async function kidOf(jwk) {
  try {
    return jwk.kid || (await calculateJwkThumbprint(stripJwkMetadata(jwk)));
  } catch (err) {
    throw new KeyError(`Invalid JWK: ${err.message}`);
  }
}

export async function importPrivateKey(material) {
  const { signing: privateJwk, decryption: encJwks, privateCount, publicCount } = selectPrivateJwks(parsePrivateKeyMaterial(material));
  const bare = stripJwkMetadata(privateJwk);
  const family = bare.kty === 'EC' ? `EC:${bare.crv}` : bare.kty;
  const signing = SIGNING_ALGS[family];
  if (!signing) throw new KeyError(`Unsupported key type ${family}; use an RSA or P-256/P-384/P-521 EC key`);

  const kid = await kidOf(privateJwk);
  const alg = privateJwk.alg && !isEncAlg(privateJwk.alg) ? privateJwk.alg : signing.alg;

  let signingKey;
  try {
    signingKey = await webcrypto.subtle.importKey('jwk', bare, signing.params, false, ['sign']);
  } catch (err) {
    throw new KeyError(`The private key could not be imported: ${err.message}`);
  }

  const decryption = [];
  for (const encJwk of encJwks) {
    const encKid = await kidOf(encJwk);
    const encBare = stripJwkMetadata(encJwk);
    for (const [encAlg, hash] of [['RSA-OAEP', 'SHA-1'], ['RSA-OAEP-256', 'SHA-256']]) {
      try {
        decryption.push({ alg: encAlg, kid: encKid, key: await webcrypto.subtle.importKey('jwk', encBare, { name: 'RSA-OAEP', hash }, false, ['decrypt']) });
      } catch (err) {
        throw new KeyError(`The encryption key (kid ${encKid}) could not be imported: ${err.message}`);
      }
    }
  }

  const publicJwk = createPublicKey(createPrivateKey({ key: bare, format: 'jwk' })).export({ format: 'jwk' });

  return {
    kid,
    alg,
    kty: bare.kty,
    signing: { key: signingKey, kid },
    decryption,
    decryptionKids: [...new Set(decryption.map((k) => k.kid))],
    keysFound: { private: privateCount, public: publicCount },
    publicJwk: { ...publicJwk, kid, use: privateJwk.use || 'sig', alg },
  };
}
