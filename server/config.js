// Server settings only. Nothing about a provider or a client lives here: the
// page sends everything it needs with each request.
import fs from 'node:fs';
import path from 'node:path';

export class SettingsError extends Error {}

function readFlag(value, fallback = false) {
  if (value === undefined || value === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
}

export function loadSettings(env = process.env) {
  const problems = [];

  const tls = { keyFile: env.TLS_KEY_FILE || null, certFile: env.TLS_CERT_FILE || null };
  if ((tls.keyFile && !tls.certFile) || (!tls.keyFile && tls.certFile)) {
    problems.push('TLS_KEY_FILE and TLS_CERT_FILE must be set together');
  }
  for (const file of [tls.keyFile, tls.certFile]) {
    if (file && !fs.existsSync(path.resolve(file))) problems.push(`TLS file not found: ${file}`);
  }

  const port = Number(env.PORT || (tls.keyFile ? 8443 : 3000));
  if (!Number.isInteger(port) || port < 1 || port > 65535) problems.push('PORT must be a valid TCP port');

  if (problems.length) {
    throw new SettingsError(`Configuration problems:\n  - ${problems.join('\n  - ')}`);
  }

  return {
    port,
    host: env.HOST || '0.0.0.0',
    tls: tls.keyFile ? tls : null,
    // Seconds a provider's discovery document is cached in memory (it is the only thing the server remembers).
    discoveryTtl: Number(env.DISCOVERY_CACHE_SECONDS || 300),
    // http:// issuers are only allowed for loopback hosts unless this is set (handy for a mock on another box).
    allowAnyInsecureIssuer: readFlag(env.ALLOW_INSECURE_ISSUER, false),
    trustProxy: readFlag(env.TRUST_PROXY, false),
  };
}
