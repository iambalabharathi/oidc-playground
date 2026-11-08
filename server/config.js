// Reads and validates the environment. Everything the app needs to know about
// the provider and the client lives here; nothing else touches process.env.
import fs from 'node:fs';
import path from 'node:path';

const CLIENT_AUTH_METHODS = ['client_secret_post', 'client_secret_basic', 'private_key_jwt', 'none'];

function trimTrailingSlash(value) {
  return String(value).replace(/\/+$/, '');
}

function readFlag(value, fallback = false) {
  if (value === undefined || value === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
}

function inferClientAuth(env) {
  if (env.CLIENT_AUTH) return env.CLIENT_AUTH;
  if (env.CLIENT_SECRET) return 'client_secret_post';
  if (env.PRIVATE_KEY_FILE || env.PRIVATE_KEY_JWK) return 'private_key_jwt';
  return 'none';
}

export class SettingsError extends Error {}

export function loadSettings(env = process.env) {
  const problems = [];

  const issuer = env.ISSUER ? trimTrailingSlash(env.ISSUER) : null;
  if (!issuer) problems.push('ISSUER is required (e.g. https://idp.e2e.itsme.services/v2)');
  else if (!/^https?:\/\//.test(issuer)) problems.push('ISSUER must be an http(s) URL');

  const clientId = env.CLIENT_ID || null;
  if (!clientId) problems.push('CLIENT_ID is required');

  const baseUrl = trimTrailingSlash(env.BASE_URL || 'http://localhost:3000');
  const redirectUri = env.REDIRECT_URI || `${baseUrl}/callback`;

  const clientAuth = inferClientAuth(env);
  if (!CLIENT_AUTH_METHODS.includes(clientAuth)) {
    problems.push(`CLIENT_AUTH must be one of ${CLIENT_AUTH_METHODS.join(', ')}`);
  }
  if (clientAuth.startsWith('client_secret') && !env.CLIENT_SECRET) {
    problems.push(`CLIENT_AUTH=${clientAuth} needs CLIENT_SECRET`);
  }
  if (clientAuth === 'private_key_jwt' && !env.PRIVATE_KEY_FILE && !env.PRIVATE_KEY_JWK) {
    problems.push('CLIENT_AUTH=private_key_jwt needs PRIVATE_KEY_FILE (JWK or PEM) or PRIVATE_KEY_JWK');
  }

  const tls = {
    keyFile: env.TLS_KEY_FILE || null,
    certFile: env.TLS_CERT_FILE || null,
  };
  if ((tls.keyFile && !tls.certFile) || (!tls.keyFile && tls.certFile)) {
    problems.push('TLS_KEY_FILE and TLS_CERT_FILE must be set together');
  }
  for (const file of [tls.keyFile, tls.certFile]) {
    if (file && !fs.existsSync(path.resolve(file))) problems.push(`TLS file not found: ${file}`);
  }
  if (env.PRIVATE_KEY_FILE && !fs.existsSync(path.resolve(env.PRIVATE_KEY_FILE))) {
    problems.push(`PRIVATE_KEY_FILE not found: ${env.PRIVATE_KEY_FILE}`);
  }

  const port = Number(env.PORT || new URL(baseUrl).port || (baseUrl.startsWith('https') ? 443 : 80));
  if (!Number.isInteger(port) || port < 1 || port > 65535) problems.push('PORT must be a valid TCP port');

  if (problems.length) {
    throw new SettingsError(`Configuration problems:\n  - ${problems.join('\n  - ')}\n\nCopy .env.example to .env and fill it in.`);
  }

  const allowInsecure = readFlag(env.ALLOW_INSECURE_ISSUER, issuer.startsWith('http://'));

  return {
    issuer,
    clientId,
    clientSecret: env.CLIENT_SECRET || null,
    clientAuth,
    baseUrl,
    redirectUri,
    port,
    host: env.HOST || '0.0.0.0',
    serviceCode: env.SERVICE_CODE || '',
    providerLabel: env.PROVIDER_LABEL || providerLabelFor(issuer),
    sessionSecret: env.SESSION_SECRET || randomSecretWithWarning(),
    allowInsecure,
    trustProxy: readFlag(env.TRUST_PROXY, false),
    decryptResponses: readFlag(env.DECRYPT_RESPONSES, false),
    idTokenSignedResponseAlg: env.ID_TOKEN_SIGNED_RESPONSE_ALG || null,
    privateKey: {
      file: env.PRIVATE_KEY_FILE || null,
      jwk: env.PRIVATE_KEY_JWK || null,
    },
    tls: tls.keyFile ? tls : null,
    logLevel: env.LOG_LEVEL || 'info',
  };
}

function providerLabelFor(issuer) {
  if (/idp\.e2e\.itsme\.services/.test(issuer)) return 'itsme · sandbox (e2e)';
  if (/idp\.prd\.itsme\.services/.test(issuer)) return 'itsme · production';
  if (/localhost|127\.0\.0\.1/.test(issuer)) return 'local provider';
  try {
    return new URL(issuer).host;
  } catch {
    return issuer;
  }
}

let warnedAboutSecret = false;
function randomSecretWithWarning() {
  if (!warnedAboutSecret) {
    warnedAboutSecret = true;
    console.warn('[config] SESSION_SECRET not set — sessions will not survive a restart.');
  }
  return [...Array(4)].map(() => Math.random().toString(36).slice(2)).join('');
}
