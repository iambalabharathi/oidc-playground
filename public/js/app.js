// The page: a request builder at "/" and the result page at "/result".
import { h, append, clear, icon, formatTime, formatIso, pretty, copyButton, truncateMiddle } from './ui.js';
import { api } from './api.js';
import {
  SCOPES, CLAIM_GROUPS, ACR_PRESETS, DEFAULT_SELECTION, TOKEN_CLAIMS,
  buildStartRequest, buildScopeList, buildClaimsParameter, requestedClaimKeys, claimLabel, shortClaimName,
} from './catalog.js';

const STORAGE_KEY = 'oidc-playground.selection.v1';
const STEPS = ['Build request', 'Authorize', 'Tokens & claims', 'UserInfo'];

const state = {
  config: null,
  configError: null,
  selection: loadSelection(),
  result: null,
  resultError: null,
  loadingResult: false,
  starting: false,
  userinfoBusy: false,
  tab: 'claims',
  userinfoTab: 'plain',
};

const root = document.getElementById('app');

// --- boot & routing ----------------------------------------------------------

function route() {
  return location.pathname.replace(/\/+$/, '') === '/result' ? 'result' : 'build';
}

function navigate(path) {
  history.pushState({}, '', path);
  onRoute();
}

async function onRoute() {
  if (route() === 'result') {
    state.loadingResult = true;
    render();
    await loadResult();
  }
  render();
}

async function loadResult() {
  state.resultError = null;
  try {
    state.result = await api.result();
  } catch (err) {
    state.resultError = err;
  } finally {
    state.loadingResult = false;
  }
}

async function loadConfig() {
  state.configError = null;
  try {
    state.config = await api.config();
    if (state.selection.serviceCode === undefined) {
      state.selection.serviceCode = state.config.provider.serviceCode || '';
    }
  } catch (err) {
    state.configError = err;
  }
}

async function boot() {
  render();
  await loadConfig();
  await onRoute();
}

window.addEventListener('popstate', onRoute);
boot();

// --- selection persistence -------------------------------------------------------

function loadSelection() {
  try {
    const saved = JSON.parse(localStorage.getItem(STORAGE_KEY) || 'null');
    if (saved && typeof saved === 'object') return { ...structuredClone(DEFAULT_SELECTION), ...saved };
  } catch {
    /* ignore corrupt storage */
  }
  return structuredClone(DEFAULT_SELECTION);
}

function saveSelection() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state.selection));
  } catch {
    /* storage may be unavailable; the page still works */
  }
}

function update(mutator, { rerender = true } = {}) {
  mutator(state.selection);
  saveSelection();
  if (rerender) render();
  else renderPreviewOnly();
}

// --- rendering ------------------------------------------------------------------

function render() {
  const focused = document.activeElement?.id;
  const scrollY = window.scrollY;
  clear(root);
  const view = route() === 'result' ? resultView() : buildView();
  append(root, [topbar(), view]);
  if (focused) document.getElementById(focused)?.focus({ preventScroll: true });
  window.scrollTo(0, scrollY);
}

function renderPreviewOnly() {
  const slot = document.getElementById('preview-slot');
  if (!slot) return render();
  clear(slot);
  append(slot, previewPanel());
}

function topbar() {
  const label = state.config?.provider?.label || 'OpenID Connect';
  return h('header.topbar', {},
    h('div.topbar-inner', {},
      h('a.brand', { href: '/', onclick: (e) => { e.preventDefault(); navigate('/'); } },
        h('span.brand-mark', {}, icon('lock', 18, { strokeWidth: 2 })),
        h('span.brand-name', 'OIDC Playground'),
      ),
      h('div.topbar-actions', {},
        h('span.pill.pill-accent', {}, h('span.dot'), label),
        h('button.btn.btn-ghost.btn-sm', { type: 'button', onclick: resetEverything }, icon('reset', 14, { strokeWidth: 2 }), ' Reset'),
      ),
    ),
  );
}

async function resetEverything() {
  try {
    await api.reset();
  } catch {
    /* session may already be gone */
  }
  state.selection = structuredClone(DEFAULT_SELECTION);
  state.selection.serviceCode = state.config?.provider?.serviceCode || '';
  saveSelection();
  state.result = null;
  state.tab = 'claims';
  state.userinfoTab = 'plain';
  navigate('/');
}

function stepper(current) {
  const items = [];
  STEPS.forEach((label, i) => {
    const n = i + 1;
    const cls = n < current ? 'is-done' : n === current ? 'is-current' : '';
    const circle = n < current ? h('span.step-num', {}, icon('check', 14, { strokeWidth: 3 })) : h('span.step-num', String(n));
    const content = [circle, h('span.step-label', label)];
    const canNavigate = n === 1 && current !== 1;
    items.push(
      canNavigate
        ? h(`a.step.${cls}`, { href: '/', onclick: (e) => { e.preventDefault(); navigate('/'); } }, content)
        : h(`div.step${cls ? '.' + cls : ''}`, { 'aria-current': n === current ? 'step' : null }, content),
    );
    if (i < STEPS.length - 1) items.push(h('span.step-sep', {}, icon('chevron', 16, { strokeWidth: 2 })));
  });
  return h('nav.stepper', { 'aria-label': 'Flow steps' }, items);
}

function card(title, subtitle, children, { id, right, extraClass = '' } = {}) {
  const head = h('div.card-head', {},
    h('div.card-title-wrap', {},
      h('h2.card-title', { id }, title),
      subtitle ? h('p.card-subtitle', {}, subtitle) : null,
    ),
    right || null,
  );
  return h(`section.card${extraClass ? '.' + extraClass : ''}`, { 'aria-labelledby': id }, head, children);
}

function kvRows(rows, { keyWidth = 'minmax(110px, 160px)' } = {}) {
  return h('div.kv', {},
    rows.map((r) =>
      h('div.kv-row', { style: { gridTemplateColumns: `${keyWidth} minmax(0, 1fr)` } },
        h('span.kv-key', r.k),
        h('span.kv-val', {}, r.node || r.v, r.hint ? h('span.kv-hint', r.hint) : null),
      ),
    ),
  );
}

// --- build view ------------------------------------------------------------------

function buildView() {
  const sel = state.selection;
  return h('main.main', {},
    stepper(1),
    h('div.page-head', {},
      h('h1.page-title', 'Build the authentication request'),
      h('p.page-lead', 'Pick scopes and individual claims. The request on the right updates live; press Authorize to send it to the provider.'),
    ),
    h('div.columns', {},
      h('section.col-main', {},
        providerCard(),
        scopesCard(sel),
        claimsCard(sel),
        optionsCard(sel),
      ),
      h('aside.col-side#preview-slot', {}, previewPanel()),
    ),
  );
}

function providerCard() {
  const cfg = state.config;
  const sel = state.selection;
  const discovery = cfg?.discovery;
  let status;
  if (state.configError) {
    status = h('span.pill.pill-err', {}, icon('alert', 14), ' Backend unreachable');
  } else if (!cfg) {
    status = h('span.pill', 'Loading…');
  } else if (discovery?.ok) {
    status = h('span.pill.pill-ok', {}, icon('check', 14, { strokeWidth: 3 }), ' Discovery loaded');
  } else {
    status = h('span.pill.pill-err', {}, icon('alert', 14), ' Discovery failed');
  }

  const fields = cfg
    ? [
        field('Issuer', h('input.input.mono', { id: 'f-issuer', type: 'text', value: cfg.provider.issuer, readonly: true, 'aria-describedby': 'issuer-hint' }), 'full', h('span.field-hint#issuer-hint', 'Set in .env (ISSUER)')),
        field('Client ID', h('input.input.mono', { id: 'f-client', type: 'text', value: cfg.provider.clientId, readonly: true })),
        field('Redirect URI', h('input.input.mono', { id: 'f-redirect', type: 'text', value: cfg.provider.redirectUri, readonly: true })),
        field('Service code (itsme®)', h('input.input.mono', {
          id: 'f-service', type: 'text', value: sel.serviceCode ?? '', placeholder: 'e.g. MYSERVICE_LOGIN', autocomplete: 'off', spellcheck: 'false',
          oninput: (e) => update((s) => { s.serviceCode = e.target.value.trim(); }, { rerender: false }),
        })),
        field('Client authentication', h('input.input.mono', { id: 'f-auth', type: 'text', value: cfg.provider.clientAuth + (cfg.provider.jwksUrl ? ' · keys at /.well-known/jwks.json' : ''), readonly: true })),
      ]
    : [];

  let endpoints = null;
  if (discovery?.ok) {
    endpoints = h('div.endpoints', {},
      Object.entries(discovery.endpoints).map(([k, v]) =>
        h('div.endpoint', {}, h('span.endpoint-key', k), h('span.endpoint-val.mono', { title: v }, v || '—')),
      ),
    );
  } else if (discovery && !discovery.ok) {
    endpoints = h('div.banner.banner-err', {},
      icon('alert', 18),
      h('div', {},
        h('strong', `${discovery.error.error}: `), discovery.error.error_description,
        h('div.banner-actions', {}, h('button.btn.btn-ghost.btn-sm', { type: 'button', onclick: async () => { await loadConfig(); render(); } }, 'Retry discovery')),
      ),
    );
  } else if (state.configError) {
    endpoints = h('div.banner.banner-err', {}, icon('alert', 18), h('div', {}, h('strong', 'Cannot reach the backend. '), 'Is the server running? ', h('code', state.configError.message)));
  }

  return card('Provider & client', ['Endpoints are read from the discovery document at ', h('code', '/.well-known/openid-configuration'), '.'],
    [h('div.fields', {}, fields), endpoints],
    { id: 'h-provider', right: status });
}

function field(label, input, span, hint) {
  const id = input.id;
  return h(`div.field${span === 'full' ? '.field-full' : ''}`, {}, h('label.field-label', { for: id }, label), input, hint || null);
}

function scopesCard(sel) {
  const chips = SCOPES.map((s) => {
    const on = s.locked || !!sel.scopes[s.id];
    const label = s.dynamic ? `service:${sel.serviceCode || 'SERVICE_CODE'}` : s.id;
    return h('button.chip', {
      type: 'button', 'aria-pressed': String(on), disabled: s.locked, title: s.hint,
      onclick: () => update((st) => { st.scopes[s.id] = !st.scopes[s.id]; }),
    }, s.locked ? icon('lock', 14) : on ? icon('check', 14, { strokeWidth: 3 }) : null, label);
  });
  return card('Scopes', ['Each scope requests a bundle of claims. ', h('code', 'openid'), ' is required for an ID token.'],
    h('div.chips', {}, chips), { id: 'h-scopes' });
}

function claimsCard(sel) {
  const selectedCount = Object.values(sel.claims).filter(Boolean).length;
  const targets = [['userinfo', 'UserInfo'], ['id_token', 'ID token'], ['both', 'Both']];
  const seg = h('div.seg', { role: 'group', 'aria-label': 'Deliver claims in' },
    targets.map(([id, label]) =>
      h('button.seg-btn', { type: 'button', 'aria-pressed': String(sel.target === id), onclick: () => update((st) => { st.target = id; }) }, label),
    ),
  );
  const right = h('div.card-tools', {}, h('span.muted.nowrap', `${selectedCount} selected`), seg);

  const groups = CLAIM_GROUPS.map((group) =>
    h('div.claim-group', {},
      h('div.claim-group-head', {}, h('h3.claim-group-title', group.title), h('span.claim-group-hint.mono', group.hint)),
      h('div.claim-grid', {}, group.claims.map((c) => claimRow(c, sel))),
      group.id === 'itsme' ? h('p.field-hint', {}, 'BENationalNumber and BEeidSn are also released by the ', h('code', 'eid'), ' scope.') : null,
    ),
  );

  return card('Claims', ['Request individual claims through the ', h('code', 'claims'), ' parameter. Mark a claim ', h('em', 'essential'), ' when your flow cannot continue without it.'],
    groups, { id: 'h-claims', right });
}

function claimRow(c, sel) {
  const on = !!sel.claims[c.id];
  const essential = on && !!sel.essential[c.id];
  const inputId = `claim-${c.id}`;
  return h(`div.claim${on ? '.is-on' : ''}`, {},
    h('input', { type: 'checkbox', id: inputId, checked: on, onchange: () => update((st) => { st.claims[c.id] = !st.claims[c.id]; }) }),
    h('label.claim-label.mono', { for: inputId, title: c.title }, c.label),
    h('button.ess', {
      type: 'button', 'aria-pressed': String(essential), disabled: !on,
      'aria-label': `${essential ? 'Unmark' : 'Mark'} ${c.label} as essential`,
      onclick: () => update((st) => { st.essential[c.id] = !st.essential[c.id]; }),
    }, 'essential'),
  );
}

function optionsCard(sel) {
  const select = (id, value, options, onchange) =>
    h('select.input', { id, onchange }, options.map((o) => h('option', { value: o.value, selected: o.value === value }, o.label)));
  const acrOptions = [...ACR_PRESETS];
  if (sel.acr && !acrOptions.some((o) => o.value === sel.acr)) acrOptions.push({ value: sel.acr, label: sel.acr });

  return card('Request options', ['Optional parameters from OpenID Connect Core §3.1.2.1. Empty fields are left out of the request.'],
    h('div.fields.fields-3', {},
      field('acr_values', select('f-acr', sel.acr, acrOptions, (e) => update((st) => { st.acr = e.target.value; }))),
      field('prompt', select('f-prompt', sel.prompt, [
        { value: '', label: 'not set' }, { value: 'none', label: 'none' }, { value: 'login', label: 'login' }, { value: 'consent', label: 'consent' }, { value: 'select_account', label: 'select_account' },
      ], (e) => update((st) => { st.prompt = e.target.value; }))),
      field('ui_locales', select('f-locales', sel.uiLocales, [
        { value: '', label: 'not set' }, { value: 'nl', label: 'nl' }, { value: 'fr', label: 'fr' }, { value: 'de', label: 'de' }, { value: 'en', label: 'en' },
      ], (e) => update((st) => { st.uiLocales = e.target.value; }))),
      field('max_age (seconds)', h('input.input.mono', { id: 'f-maxage', type: 'number', min: 0, value: sel.maxAge, placeholder: 'e.g. 300', oninput: (e) => update((st) => { st.maxAge = e.target.value; }, { rerender: false }) })),
      field('login_hint', h('input.input.mono', { id: 'f-hint', type: 'text', value: sel.loginHint, placeholder: 'phone number or e-mail', autocomplete: 'off', oninput: (e) => update((st) => { st.loginHint = e.target.value; }, { rerender: false }) })),
      h('div.field.field-check', {},
        h('input', { type: 'checkbox', id: 'f-pkce', checked: sel.pkce, onchange: () => update((st) => { st.pkce = !st.pkce; }) }),
        h('label.field-label', { for: 'f-pkce' }, 'PKCE ', h('span.muted', '(S256 code challenge)')),
      ),
    ),
    { id: 'h-options' });
}

function previewPanel() {
  const sel = state.selection;
  const cfg = state.config;
  const body = buildStartRequest(sel, sel.serviceCode);
  const claimsParam = body.claims;
  const endpoint = cfg?.discovery?.ok ? cfg.discovery.endpoints.authorization_endpoint : (cfg ? `${cfg.provider.issuer}/… (from discovery)` : '…');

  const params = [
    { k: 'response_type', v: 'code' },
    { k: 'client_id', v: cfg?.provider.clientId || '…' },
    { k: 'redirect_uri', v: cfg?.provider.redirectUri || '…' },
    { k: 'scope', v: body.scopes.join(' ') },
    { k: 'state', v: '{generated on Authorize}' },
    { k: 'nonce', v: '{generated on Authorize}' },
  ];
  if (body.pkce) params.push({ k: 'code_challenge', v: '{S256 of a fresh verifier}' }, { k: 'code_challenge_method', v: 'S256' });
  for (const k of ['acr_values', 'prompt', 'ui_locales', 'max_age', 'login_hint']) {
    if (body[k] !== undefined) params.push({ k, v: String(body[k]) });
  }
  if (claimsParam) {
    const n = requestedClaimKeys(claimsParam).length;
    params.push({ k: 'claims', v: `{ ${Object.keys(claimsParam).map((t) => `"${t}": { … ${n} }`).join(', ')} }  — see below` });
  }

  const canStart = !!cfg?.discovery?.ok && !state.starting;
  const previewUrl = () => {
    const u = new URL(cfg?.discovery?.ok ? endpoint : 'https://provider.example/authorize');
    for (const p of params) if (p.k !== 'claims') u.searchParams.set(p.k, p.v);
    if (claimsParam) u.searchParams.set('claims', JSON.stringify(claimsParam));
    return u.href;
  };

  return [
    card('Authorization request', null, [
      h('div.endpoint-box.mono', endpoint),
      kvRows(params, { keyWidth: 'minmax(120px, 180px)' }),
    ], { id: 'h-preview', right: h('span.tag.tag-ok.mono', 'GET') }),
    card('claims parameter', ['Sent URL-encoded as ', h('code', 'claims='), '. ', h('code', 'null'), ' means voluntary.'],
      h('pre.code', claimsParam ? pretty(claimsParam) : '{ }  // no individual claims selected'),
      { id: 'h-claimsjson' }),
    h('div.cta', {},
      h('button.btn.btn-primary.btn-lg', { type: 'button', disabled: !canStart, onclick: startAuthorization },
        state.starting ? 'Preparing request…' : `Authorize with ${providerShortName()}`, icon('arrow', 18)),
      copyButton('Copy authorization URL (preview)', previewUrl),
      state.startError ? h('div.banner.banner-err', {}, icon('alert', 18), h('div', {}, state.startError)) : null,
      h('p.cta-note', {}, 'You leave for the provider and come back to ', h('code', '/callback'), ' with a one-time code. state, nonce and the PKCE verifier are generated server-side when you click.'),
    ),
  ];
}

function providerShortName() {
  const label = state.config?.provider?.label || 'the provider';
  return label.split('·')[0].trim();
}

async function startAuthorization() {
  state.starting = true;
  state.startError = null;
  renderPreviewOnly();
  try {
    const body = buildStartRequest(state.selection, state.selection.serviceCode);
    const { url } = await api.start(body);
    window.location.assign(url);
  } catch (err) {
    state.starting = false;
    const errors = err.body?.errors;
    state.startError = errors ? `Request rejected: ${errors.join('; ')}` : err.message;
    renderPreviewOnly();
  }
}

// --- result view ----------------------------------------------------------------

function resultView() {
  const r = state.result;
  if (state.loadingResult || (!r && !state.resultError)) {
    return h('main.main', {}, stepper(3), h('div.card.card-center', {}, h('div.spinner'), h('p.muted', 'Loading the result…')));
  }
  if (state.resultError) {
    return h('main.main', {}, stepper(3), h('div.banner.banner-err', {}, icon('alert', 18), h('div', {}, h('strong', 'Could not load the result. '), state.resultError.message)));
  }
  if (r.status === 'empty') {
    return h('main.main', {}, stepper(1),
      h('div.card.card-center', {},
        h('h1.page-title', 'Nothing here yet'),
        h('p.muted', 'This browser session has no completed authorization. Build a request and authorize to see tokens and claims.'),
        h('a.btn.btn-primary', { href: '/', onclick: (e) => { e.preventDefault(); navigate('/'); } }, 'Build a request', icon('arrow', 18)),
      ),
    );
  }
  if (r.status === 'error') return errorView(r);

  const current = r.userinfo ? 4 : 3;
  return h('main.main', {},
    stepper(current),
    h('div.banner.banner-ok', { role: 'status' },
      icon('circleCheck', 20),
      h('div', {},
        h('div', {}, h('strong', 'Callback received'), ' — ', h('code', 'state'), ' matches, code exchanged for tokens.'),
        h('code.mono.small.break', r.callback.url),
      ),
    ),
    h('div.page-head', {},
      h('h1.page-title', 'Tokens & ID token claims'),
      h('p.page-lead', 'The token endpoint returned an ID token and an access token. Below is everything the ID token says — about the user and about itself.'),
    ),
    h('div.columns', {},
      h('section.col-main', {}, idTokenCard(r), userinfoCard(r)),
      h('aside.col-side', {}, tokenResponseCard(r), checksCard('ID token checks', 'OpenID Connect Core §3.1.3.7', r.idToken.checks, 'h-checks'), requestSentCard(r)),
    ),
    h('div.actions', {},
      h('a.btn.btn-primary.btn-lg', { href: '/', onclick: (e) => { e.preventDefault(); navigate('/'); } }, icon('reset', 16, { strokeWidth: 2 }), 'Start a new request'),
      copyButton('Copy result as JSON', () => pretty(r)),
    ),
  );
}

function errorView(r) {
  const e = r.error || {};
  return h('main.main', {},
    stepper(e.stage === 'authorization' || e.stage === 'callback' ? 2 : 3),
    h('div.banner.banner-err', { role: 'alert' },
      icon('alert', 20),
      h('div', {},
        h('div', {}, h('strong', `${e.error || 'error'}`), e.stage ? h('span.muted', ` · during ${e.stage}`) : null),
        h('div', e.error_description || ''),
        r.callback?.url ? h('code.mono.small.break', r.callback.url) : null,
      ),
    ),
    h('div.page-head', {},
      h('h1.page-title', 'The flow did not complete'),
      h('p.page-lead', e.stage === 'authorization'
        ? 'The provider sent back an error instead of an authorization code.'
        : e.stage === 'callback'
          ? 'The callback could not be matched to a request from this browser.'
          : 'The authorization code could not be exchanged or the ID token failed validation.'),
    ),
    h('div.columns', {},
      h('section.col-main', {}, r.request ? requestSentCard(r, { open: true }) : null),
      h('aside.col-side', {}, r.callback?.query ? card('Callback parameters', null, kvRows(Object.entries(r.callback.query).map(([k, v]) => ({ k, v }))), { id: 'h-cbq' }) : null),
    ),
    h('div.actions', {},
      h('a.btn.btn-primary.btn-lg', { href: '/', onclick: (ev) => { ev.preventDefault(); navigate('/'); } }, icon('reset', 16, { strokeWidth: 2 }), 'Back to the request builder'),
    ),
  );
}

function tabs(items, current, onPick) {
  return h('div.tabs', { role: 'tablist' },
    items.map(([id, label]) => h('button.tab', { type: 'button', role: 'tab', 'aria-selected': String(current === id), onclick: () => onPick(id) }, label)),
  );
}

function idTokenCard(r) {
  const { header, payload, format, checks } = r.idToken;
  const allOk = checks.every((c) => c.ok);
  const right = h(`span.pill.${allOk ? 'pill-ok' : 'pill-err'}`, {}, icon(allOk ? 'check' : 'alert', 14, { strokeWidth: 3 }), allOk ? ' Valid' : ' Check failed');
  const subtitle = format === 'jwe'
    ? ['Encrypted JWT (JWE) · ', h('code', `${header?.alg} / ${header?.enc}`), ' · decrypted with the RP key']
    : ['Signed JWT · ', h('code', header?.alg || '?'), header?.kid ? [' · kid ', h('code', header.kid)] : null];

  let panel;
  if (state.tab === 'decoded') panel = decodedPanel(r);
  else if (state.tab === 'raw') panel = rawJwtPanel(r.tokens.id_token);
  else panel = idTokenClaimsPanel(r);

  return card('ID token', subtitle, [
    tabs([['claims', 'Claims'], ['decoded', 'Decoded'], ['raw', 'Raw JWT']], state.tab, (id) => { state.tab = id; render(); }),
    h('div', { role: 'tabpanel' }, panel),
  ], { id: 'h-idtoken', right });
}

function idTokenClaimsPanel(r) {
  const payload = r.idToken.payload;
  const requested = requestedClaimKeys(r.request?.selection?.claims || null);
  const requestedIdToken = Object.keys(r.request?.selection?.claims?.id_token || {});
  const essential = new Set(Object.entries(r.request?.selection?.claims?.id_token || {}).filter(([, v]) => v?.essential).map(([k]) => k));

  const userKeys = Object.keys(payload).filter((k) => !TOKEN_CLAIMS.includes(k));
  const missing = requestedIdToken.filter((k) => !(k in payload));
  const rows = [
    ...userKeys.map((k) => ({ key: k, value: payload[k], missing: false, requested: requested.includes(k) })),
    ...missing.map((k) => ({ key: k, value: undefined, missing: true, requested: true })),
  ];

  const tokenRows = TOKEN_CLAIMS.filter((k) => k in payload).map((k) => {
    const v = payload[k];
    let hint = null;
    if (k === 'exp') hint = `${formatTime(v)} · ${Math.max(0, v - Math.floor(Date.now() / 1000))} s left`;
    if (k === 'iat' || k === 'auth_time') hint = formatTime(v);
    if (k === 'aud') hint = 'equals client_id';
    if (k === 'nonce') hint = 'echoes the nonce from the request';
    if (k === 'acr') hint = 'authentication level achieved';
    return { k, v: Array.isArray(v) ? v.join(', ') : String(v), hint };
  });

  return h('div.stack-lg', {},
    h('div.stack-sm', {},
      h('h3.subhead', 'About the user'),
      rows.length ? claimsTable(rows, { essential, showRequested: true }) : h('p.muted', 'The ID token carries no user claims; request some for the ID token, or look at UserInfo.'),
    ),
    h('div.stack-sm', {}, h('h3.subhead', 'About the token'), kvRows(tokenRows, { keyWidth: 'minmax(100px, 140px)' })),
  );
}

function claimsTable(rows, { essential = new Set(), showRequested = false } = {}) {
  return h('div.table-wrap', {},
    h('div.table', {},
      h('div.table-head', {}, h('span', 'Label'), h('span', 'Claim'), h('span', 'Value'), h('span', { 'aria-label': 'Returned' })),
      rows.map((row) =>
        h(`div.table-row${row.missing ? '.is-missing' : ''}`, {},
          h('span.cell-label', claimLabel(row.key)),
          h('span.cell-claim', {},
            h('span.mono.ellipsis', { title: row.key }, shortClaimName(row.key)),
            essential.has(row.key) ? h('span.tag.tag-accent', 'essential') : null,
          ),
          h('span.cell-value', {}, valueNode(row)),
          h('span.cell-status', {}, row.missing
            ? icon('dash', 16, { label: 'Not returned' })
            : h('span.ok-icon', {}, icon('check', 16, { strokeWidth: 3, label: 'Returned' }))),
        ),
      ),
    ),
  );
}

function valueNode(row) {
  if (row.missing) return h('span.muted.italic', 'not returned');
  const v = row.value;
  if (typeof v === 'boolean') return h('span.tag.tag-ok.mono', {}, icon('check', 12, { strokeWidth: 3 }), String(v));
  if (v !== null && typeof v === 'object') return h('pre.code.code-inline', pretty(v));
  if (typeof v === 'string' && /^https?:\/\//.test(v)) return h('a.mono.break', { href: v, target: '_blank', rel: 'noopener noreferrer' }, v);
  return h('span.mono.break', String(v));
}

function decodedPanel(r) {
  const { header, payload, format } = r.idToken;
  const block = (dotClass, title, body) => h('div.stack-xs', {},
    h('div.legend-item', {}, h(`span.dot.${dotClass}`), h('span.subhead-caps', title)),
    body,
  );
  return h('div.stack-md', {},
    block('dot-header', format === 'jwe' ? 'JWE header' : 'Header', h('pre.code', pretty(header))),
    block('dot-payload', 'Payload', h('pre.code', pretty(payload))),
    block('dot-sig', 'Signature', h('div.note', {},
      format === 'jwe'
        ? ['The token was decrypted with the RP private key; the nested JWS signature was verified against the provider’s ', h('code', 'jwks_uri'), '.']
        : [h('code', header?.alg || '?'), ' over ', h('code', 'base64url(header).base64url(payload)'), ', verified with the public key', header?.kid ? [' ', h('code', `kid=${header.kid}`)] : null, ' from the provider’s ', h('code', 'jwks_uri'), '.'],
    )),
  );
}

function rawJwtPanel(jwt) {
  const parts = String(jwt).split('.');
  const colored = parts.length === 3
    ? [h('span.jwt-header', parts[0]), h('span.jwt-dot', '.'), h('span.jwt-payload', parts[1]), h('span.jwt-dot', '.'), h('span.jwt-sig', parts[2])]
    : [h('span.jwt-payload', jwt)];
  return h('div.stack-sm', {},
    h('pre.code.break-all', {}, colored),
    h('div.row-between', {},
      parts.length === 3
        ? h('div.legend', {}, h('span.legend-item', {}, h('span.dot.dot-header'), 'Header'), h('span.legend-item', {}, h('span.dot.dot-payload'), 'Payload'), h('span.legend-item', {}, h('span.dot.dot-sig'), 'Signature'))
        : h('span.muted', `${parts.length} segments (encrypted token)`),
      copyButton('Copy JWT', jwt, 'btn-sm'),
    ),
  );
}

function tokenResponseCard(r) {
  const t = r.tokens;
  const rows = [
    { k: 'token_type', v: t.token_type },
    { k: 'expires_in', v: t.expires_in == null ? '—' : `${t.expires_in} s`, hint: t.receivedAt ? `received ${formatIso(t.receivedAt)}` : null },
    { k: 'scope', v: t.scope || '—' },
    { k: 'access_token', node: tokenValue(t.access_token) },
  ];
  if (t.refresh_token) rows.push({ k: 'refresh_token', node: tokenValue(t.refresh_token) });
  rows.push({ k: 'id_token', node: tokenValue(t.id_token) });
  return card('Token response', null, [
    h('div.endpoint-box.mono', state.config?.discovery?.endpoints?.token_endpoint || 'token endpoint'),
    kvRows(rows, { keyWidth: 'minmax(100px, 120px)' }),
  ], { id: 'h-tokenresp', right: h('span.tag.tag-ok.mono', 'POST 200') });
}

function tokenValue(value) {
  return h('span.token-val', {}, h('span.mono.break', { title: value }, truncateMiddle(value, 44)), copyButton('Copy', value, 'btn-xs'));
}

function checksCard(title, subtitle, checks, id) {
  return card(title, subtitle,
    h('ul.checks', {}, checks.map((c) =>
      h(`li.check${c.ok ? '' : '.is-failed'}`, {},
        h('span.check-icon', {}, icon(c.ok ? 'check' : 'alert', 12, { strokeWidth: 3 })),
        h('span.check-body', {}, h('span.check-title', c.title), h('span.check-detail.mono', c.detail || '')),
      ),
    )),
    { id });
}

function requestSentCard(r, { open = false } = {}) {
  const req = r.request;
  if (!req) return null;
  const details = h('details.details', { open: open || null },
    h('summary.details-summary', {}, 'Request sent', h('span.muted', ` · ${req.params.length} parameters`)),
    h('div.stack-sm', {},
      h('div.endpoint-box.mono.break', new URL(req.url).origin + new URL(req.url).pathname),
      kvRows(req.params.map((p) => ({ k: p.k, v: p.v })), { keyWidth: 'minmax(110px, 170px)' }),
      copyButton('Copy full URL', req.url, 'btn-sm'),
    ),
  );
  return h('section.card', {}, details);
}

function userinfoCard(r) {
  const ui = r.userinfo;
  const endpoint = state.config?.discovery?.endpoints?.userinfo_endpoint || 'userinfo endpoint';

  if (!ui) {
    return card('UserInfo', ['Call the ', h('code', 'userinfo_endpoint'), ' with the access token and see the plain values the provider returns.'],
      h('div.cta.cta-inline', {},
        h('div.endpoint-box.mono', `GET ${endpoint}`),
        h('button.btn.btn-primary.btn-lg', { type: 'button', disabled: state.userinfoBusy, onclick: callUserinfo },
          state.userinfoBusy ? 'Calling userinfo…' : 'Call the userinfo endpoint', icon('arrow', 18)),
        state.userinfoError ? h('div.banner.banner-err', {}, icon('alert', 18), h('div', {}, state.userinfoError)) : null,
      ),
      { id: 'h-userinfo' });
  }

  const statusTag = h(`span.tag.mono.${ui.response.status === 200 ? 'tag-ok' : 'tag-err'}`, `GET ${ui.response.status}`);
  const meta = h('div.meta-row', {},
    h('span.mono', ui.request.url),
    h('span.muted', ` · ${ui.response.contentType.split(';')[0] || 'no content-type'} · ${ui.response.durationMs} ms · ${formatIso(ui.fetchedAt)}`),
  );

  if (!ui.ok) {
    return card('UserInfo', null, [
      meta,
      h('div.banner.banner-err', {}, icon('alert', 18), h('div', {}, h('strong', `${ui.error.error}: `), ui.error.error_description)),
      ui.response.body ? h('pre.code', ui.response.body) : null,
      h('button.btn.btn-ghost', { type: 'button', onclick: callUserinfo }, 'Try again'),
    ], { id: 'h-userinfo', right: statusTag });
  }

  const claims = ui.claims || {};
  const requestedUserinfo = Object.keys(r.request?.selection?.claims?.userinfo || {});
  const essential = new Set(Object.entries(r.request?.selection?.claims?.userinfo || {}).filter(([, v]) => v?.essential).map(([k]) => k));
  const keys = ['sub', ...Object.keys(claims).filter((k) => k !== 'sub')];
  const missing = requestedUserinfo.filter((k) => !(k in claims));
  const rows = [
    ...keys.filter((k) => k in claims).map((k) => ({ key: k, value: claims[k], missing: false })),
    ...missing.map((k) => ({ key: k, value: undefined, missing: true })),
  ];
  const returned = requestedUserinfo.filter((k) => k in claims);
  const idTokenPayload = r.idToken.payload;
  const differs = returned.filter((k) => k in idTokenPayload && JSON.stringify(idTokenPayload[k]) !== JSON.stringify(claims[k]));

  const summary = requestedUserinfo.length
    ? h('div.stats', {},
        h('div.stat', {}, h('span.stat-num', String(requestedUserinfo.length)), h('span.stat-label', 'requested')),
        h('div.stat.stat-ok', {}, h('span.stat-num', String(returned.length)), h('span.stat-label', 'returned')),
        h(`div.stat${missing.length ? '.stat-warn' : ''}`, {}, h('span.stat-num', String(missing.length)), h('span.stat-label', 'not returned')),
      )
    : null;
  const notes = [];
  if (missing.length) notes.push({ ok: false, text: `Not returned: ${missing.map(shortClaimName).join(', ')}. Voluntary claims may be omitted without an error.` });
  const missingEssential = missing.filter((k) => essential.has(k));
  if (missingEssential.length) notes.push({ ok: false, text: `Essential claim(s) missing: ${missingEssential.map(shortClaimName).join(', ')}.` });
  else if (essential.size) notes.push({ ok: true, text: `All essential claims were returned (${[...essential].map(shortClaimName).join(', ')}).` });
  if (differs.length) notes.push({ ok: false, text: `Values differ from the ID token for: ${differs.map(shortClaimName).join(', ')}.` });
  else if (returned.some((k) => k in idTokenPayload)) notes.push({ ok: true, text: 'Every value that is also in the ID token is identical.' });

  const panel = state.userinfoTab === 'raw'
    ? h('pre.code', ui.response.body)
    : claimsTable(rows, { essential });

  return card('UserInfo', [`${Object.keys(claims).length} claims · `, h('code', ui.format === 'json' ? 'application/json' : ui.format === 'jwt' ? 'signed JWT (verified)' : 'encrypted JWT (decrypted + verified)')], [
    meta,
    tabs([['plain', 'Plain values'], ['raw', ui.format === 'json' ? 'Raw JSON' : 'Raw response']], state.userinfoTab, (id) => { state.userinfoTab = id; render(); }),
    h('div', { role: 'tabpanel' }, panel),
    summary,
    notes.length ? h('ul.notes', {}, notes.map((n) => h(`li.note-item${n.ok ? '.is-ok' : '.is-warn'}`, {}, icon(n.ok ? 'check' : 'dash', 12, { strokeWidth: 3 }), h('span', n.text)))) : null,
    ui.checks?.length ? h('ul.checks.checks-compact', {}, ui.checks.map((c) => h(`li.check${c.ok ? '' : '.is-failed'}`, {}, h('span.check-icon', {}, icon(c.ok ? 'check' : 'alert', 12, { strokeWidth: 3 })), h('span.check-body', {}, h('span.check-title', c.title), h('span.check-detail.mono', c.detail || ''))))) : null,
    h('div.row-between', {}, copyButton('Copy userinfo JSON', () => pretty(claims), 'btn-sm'), h('button.btn.btn-ghost.btn-sm', { type: 'button', onclick: callUserinfo }, 'Call again')),
  ], { id: 'h-userinfo', right: statusTag });
}

async function callUserinfo() {
  state.userinfoBusy = true;
  state.userinfoError = null;
  render();
  try {
    const userinfo = await api.userinfo();
    state.result.userinfo = userinfo;
    state.userinfoTab = 'plain';
  } catch (err) {
    state.userinfoError = err.message;
  } finally {
    state.userinfoBusy = false;
    render();
  }
}

// expose a little for debugging in the console
window.__oidcPlayground = { state, buildScopeList, buildClaimsParameter };
