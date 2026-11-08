// Entry point: load settings and keys, build the app, listen over HTTP or HTTPS.
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import path from 'node:path';
import { loadSettings, SettingsError } from './config.js';
import { loadRpKeys } from './keys.js';
import { createOidc } from './oidc.js';
import { createApp } from './app.js';

async function main() {
  let settings;
  try {
    settings = loadSettings();
  } catch (err) {
    if (err instanceof SettingsError) {
      console.error(err.message);
      process.exit(1);
    }
    throw err;
  }

  const rpKeys = await loadRpKeys(settings);
  const oidc = createOidc(settings, rpKeys);
  const app = createApp({ settings, oidc, rpKeys });

  const server = settings.tls
    ? https.createServer(
        {
          key: fs.readFileSync(path.resolve(settings.tls.keyFile)),
          cert: fs.readFileSync(path.resolve(settings.tls.certFile)),
        },
        app,
      )
    : http.createServer(app);

  server.listen(settings.port, settings.host, () => {
    console.log(`OIDC playground  →  ${settings.baseUrl}`);
    console.log(`  provider       ${settings.providerLabel}`);
    console.log(`  issuer         ${settings.issuer}`);
    console.log(`  client_id      ${settings.clientId}`);
    console.log(`  client auth    ${settings.clientAuth}${rpKeys ? ` (kid ${rpKeys.kid})` : ''}`);
    console.log(`  redirect_uri   ${settings.redirectUri}`);
    if (settings.tls) console.log('  tls            on');
  });

  // Warm up discovery so the first click is fast; failures are shown in the UI.
  oidc
    .getConfiguration()
    .then((configuration) => {
      const md = configuration.serverMetadata();
      console.log(`  discovery      ok · ${md.authorization_endpoint}`);
    })
    .catch((err) => {
      console.warn(`  discovery      failed · ${err.message}${err.cause ? ` (${err.cause.code || err.cause.message})` : ''}`);
    });
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
