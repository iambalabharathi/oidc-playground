// Small JOSE helpers: decoding for display, at_hash verification and
// UserInfo responses that arrive as JWT (signed) or JWE (encrypted).
import { createHash } from 'node:crypto';
import * as jose from 'jose';

export function base64urlToBuffer(segment) {
  return Buffer.from(segment.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

export function decodeJwtForDisplay(token) {
  if (typeof token !== 'string') return null;
  const parts = token.split('.');
  const header = safeJson(parts[0]);
  if (parts.length === 5) {
    return { format: 'jwe', header, payload: null, parts };
  }
  if (parts.length === 3) {
    return { format: 'jws', header, payload: safeJson(parts[1]), parts };
  }
  return { format: 'opaque', header: null, payload: null, parts };
}

function safeJson(segment) {
  try {
    return JSON.parse(base64urlToBuffer(segment).toString('utf8'));
  } catch {
    return null;
  }
}

const HASH_FOR_ALG = {
  256: 'sha256',
  384: 'sha384',
  512: 'sha512',
};

// OpenID Connect Core §3.1.3.6: at_hash = base64url(left half of HASH(access_token)),
// where HASH is the hash of the ID token's signing algorithm (RS256 → SHA-256).
export function computeAtHash(accessToken, alg = 'RS256') {
  const bits = String(alg).match(/(256|384|512)$/)?.[1] || '256';
  const digest = createHash(HASH_FOR_ALG[bits]).update(accessToken, 'ascii').digest();
  return digest.subarray(0, digest.length / 2).toString('base64url');
}

/**
 * Turn a raw UserInfo HTTP response into { format, claims, checks } where
 * format is json | jwt | jwe. Signed responses are verified against the
 * provider's JWKS; encrypted ones are decrypted with our private keys first.
 */
export async function parseUserinfoBody({ contentType, body, issuer, clientId, jwksUri, decryptionKeys = [], expectedSub }) {
  const checks = [];
  const type = (contentType || '').toLowerCase();

  if (type.includes('application/jwt') || looksLikeJwt(body)) {
    let token = body.trim();
    let format = 'jwt';
    let protectedHeader = jose.decodeProtectedHeader(token);

    if (token.split('.').length === 5) {
      format = 'jwe';
      const sameKid = protectedHeader.kid ? decryptionKeys.filter((k) => k.kid === protectedHeader.kid) : [];
      const pool = sameKid.length ? sameKid : decryptionKeys;
      const candidate = pool.find((k) => k.alg === protectedHeader.alg) || pool[0];
      if (!candidate) {
        throw new Error(`UserInfo response is encrypted (${protectedHeader.alg}) but no private key is configured. Set PRIVATE_KEY_FILE and DECRYPT_RESPONSES=1.`);
      }
      const { plaintext } = await jose.compactDecrypt(token, candidate.key);
      checks.push({ title: 'Decrypted with the RP private key', detail: `${protectedHeader.alg} · ${protectedHeader.enc}`, ok: true });
      token = Buffer.from(plaintext).toString('utf8').trim();
      if (!looksLikeJwt(token)) {
        const claims = JSON.parse(token);
        checks.push(subCheck(claims, expectedSub));
        return { format, claims, checks, header: protectedHeader };
      }
      protectedHeader = jose.decodeProtectedHeader(token);
    }

    const unverified = jose.decodeJwt(token);
    const JWKS = jose.createRemoteJWKSet(new URL(jwksUri));
    const options = {};
    if (unverified.iss) options.issuer = issuer;
    if (unverified.aud) options.audience = clientId;
    const { payload } = await jose.jwtVerify(token, JWKS, options);
    checks.push({ title: 'Signature verified', detail: `${protectedHeader.alg}${protectedHeader.kid ? ` · kid ${protectedHeader.kid}` : ''} · ${jwksUri}`, ok: true });
    if (unverified.iss) checks.push({ title: 'iss equals the issuer', detail: String(payload.iss), ok: true });
    if (unverified.aud) checks.push({ title: 'aud contains client_id', detail: [].concat(payload.aud).join(', '), ok: true });
    checks.push(subCheck(payload, expectedSub));
    return { format, claims: stripJwtRegisteredClaims(payload), checks, header: protectedHeader };
  }

  const claims = JSON.parse(body);
  checks.push(subCheck(claims, expectedSub));
  return { format: 'json', claims, checks, header: null };
}

function looksLikeJwt(text) {
  const t = String(text || '').trim();
  return /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*(\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*)?$/.test(t);
}

function subCheck(claims, expectedSub) {
  const ok = !!expectedSub && claims && claims.sub === expectedSub;
  return {
    title: 'sub equals the ID token subject',
    detail: ok ? String(claims.sub) : `userinfo sub ${claims?.sub ?? '(none)'} ≠ id_token sub ${expectedSub}`,
    ok,
  };
}

function stripJwtRegisteredClaims(payload) {
  // Keep iss/aud out of the "user" claims table; they are reported as checks.
  const { iss, aud, exp, iat, nbf, jti, ...rest } = payload;
  return rest;
}
