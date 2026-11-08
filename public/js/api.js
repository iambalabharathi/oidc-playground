// Calls to our own backend. The browser never talks to the provider directly
// except for the redirect to the authorization endpoint.

async function request(path, init = {}) {
  const response = await fetch(path, {
    ...init,
    headers: { Accept: 'application/json', ...(init.body ? { 'Content-Type': 'application/json' } : {}), ...(init.headers || {}) },
    credentials: 'same-origin',
  });
  let body = null;
  const text = await response.text();
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = { error: 'bad_response', error_description: text.slice(0, 300) };
  }
  if (!response.ok) {
    const err = new Error(body?.error_description || body?.detail?.error_description || body?.error || `HTTP ${response.status}`);
    err.status = response.status;
    err.body = body;
    throw err;
  }
  return body;
}

export const api = {
  config: () => request('/api/config'),
  start: (selection) => request('/api/auth/start', { method: 'POST', body: JSON.stringify(selection) }),
  result: () => request('/api/result'),
  userinfo: () => request('/api/userinfo', { method: 'POST', body: '{}' }),
  reset: () => request('/api/reset', { method: 'POST', body: '{}' }),
};
