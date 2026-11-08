// Calls to our own stateless backend. Every call carries what it needs; the
// server remembers nothing between calls.

async function post(path, body) {
  let response;
  try {
    response = await fetch(path, {
      method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify(body ?? {}),
    });
  } catch (err) {
    return { ok: false, error: { error: 'network_error', error_description: `Cannot reach the backend (${err.message}). Is the server running?` } };
  }
  const text = await response.text();
  try {
    const json = JSON.parse(text);
    if (json && typeof json === 'object' && 'ok' in json) return json;
    return { ok: false, error: { error: 'bad_response', error_description: text.slice(0, 300) } };
  } catch {
    return { ok: false, error: { error: 'bad_response', error_description: `HTTP ${response.status}: ${text.slice(0, 300)}` } };
  }
}

export const api = {
  discover: (issuer) => post('/api/discover', { issuer }),
  token: (body) => post('/api/token', body),
  userinfo: (body) => post('/api/userinfo', body),
  inspectKey: (privateKey) => post('/api/keys/inspect', { private_key: privateKey }),
};
