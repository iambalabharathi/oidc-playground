// Entry point: load server settings, build the app, listen over HTTP or HTTPS.
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import path from 'node:path';
import { loadSettings, SettingsError } from './config.js';
import { createOidc } from './oidc.js';
import { createApp } from './app.js';

function main() {
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

  const oidc = createOidc(settings);
  const app = createApp({ settings, oidc });

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
    const scheme = settings.tls ? 'https' : 'http';
    console.log(`OIDC playground  →  ${scheme}://localhost:${settings.port}/`);
    console.log(`  redirect URI   ${scheme}://localhost:${settings.port}/   (default: the page itself; the form accepts another registered one)`);
    console.log(`  helper API     ${scheme}://localhost:${settings.port}/api  (for providers without CORS)`);
    console.log('  state          none kept server-side');
  });
}

main();
