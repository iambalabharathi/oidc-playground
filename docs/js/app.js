// A static page (GitHub Pages friendly): the request builder, the provider's redirect
// target and the result all live on this one URL. Everything the flow needs is kept in
// this browser tab; the code exchange runs in the browser (oauth4webapi) or, for
// providers without CORS, through the optional local helper.
import { h, append, clear, icon, formatTime, formatIso, pretty, copyButton, truncateMiddle } from './ui.js';
import { backendFor } from './backends.js';
import {
  SCOPES, CLAIM_GROUPS, ACR_PRESETS, DEFAULT_SELECTION, TOKEN_CLAIMS, ISSUER_PRESETS, CLIENT_AUTH_METHODS,
  buildStartRequest, buildAuthorizationParams, requestedClaimKeys, claimLabel, shortClaimName,
} from './catalog.js';

const FORM_KEY = 'oidc-playground.form.v2'; // localStorage: everything that is not a secret
const SECRETS_KEY = 'oidc-playground.secrets.v2'; // sessionStorage: client secret, private key (this tab only)
const PENDING_KEY = 'oidc-playground.pending.v2'; // sessionStorage: what we must remember across the redirect
const RESULT_KEY = 'oidc-playground.result.v2'; // sessionStorage: the last result, so a reload keeps it
const VIEW_KEY = 'oidc-playground.view.v2'; // sessionStorage: which view a reload comes back to
const STEPS = ['Build request', 'Authorize', 'Tokens & claims', 'UserInfo'];

const state = {
  form: loadJson(localStorage, FORM_KEY, structuredClone(DEFAULT_SELECTION)),
  secrets: loadJson(sessionStorage, SECRETS_KEY, { clientSecret: '', privateKey: '' }),
  discovery: null, // { issuer, provider } | { issuer, error }
  discovering: false,
  keyInfo: null, // { key } | { error }
  showSecret: false,
  starting: false,
  startError: null,
  result: loadJson(sessionStorage, RESULT_KEY, null),
  view: sessionStorage.getItem(VIEW_KEY) === 'result' ? 'result' : 'build',
  exchanging: false,
  userinfoBusy: false,
  userinfoError: null,
  tab: 'claims',
  userinfoTab: 'plain',
};

const root = document.getElementById('app');
// The page itself is the redirect URI: on GitHub Pages that is https://<user>.github.io/<repo>/
const redirectUri = `${location.origin}${location.pathname}`;
const backend = () => backendFor(state.form);

// --- storage ------------------------------------------------------------------------

function loadJson(storage, key, fallback) {
  try {
    const saved = JSON.parse(storage.getItem(key) || 'null');
    if (saved && typeof saved === 'object') return Array.isArray(fallback) ? saved : { ...fallback, ...saved };
  } catch {
    /* corrupt or unavailable storage */
  }
  return fallback;
}

function saveJson(storage, key, value) {
  try {
    if (value === null || value === undefined) storage.removeItem(key);
    else storage.setItem(key, JSON.stringify(value));
  } catch {
    /* storage may be unavailable; the page still works for this view */
  }
}

const saveForm = () => saveJson(localStorage, FORM_KEY, state.form);
const saveSecrets = () => saveJson(sessionStorage, SECRETS_KEY, state.secrets);
const saveResult = () => saveJson(sessionStorage, RESULT_KEY, state.result);
const saveView = () => {
  try {
    sessionStorage.setItem(VIEW_KEY, state.view);
  } catch {
    /* ignore */
  }
};

// --- boot & routing -------------------------------------------------------------------

function isCallback() {
  const q = new URLSearchParams(location.search);
  return q.has('code') || q.has('error') || (q.has('state') && q.has('iss'));
}

function show(view) {
  state.view = view;
  saveView();
  render();
  window.scrollTo(0, 0);
}

async function boot() {
  render();
  if (isCallback()) {
    await handleCallback();
  } else if (state.form.issuer) {
    await loadDiscovery();
  }
}

boot();

// --- discovery & key inspection ---------------------------------------------------------

async function loadDiscovery() {
  const issuer = state.form.issuer.trim();
  if (!issuer) {
    state.discovery = null;
    return render();
  }
  state.discovering = true;
  render();
  const res = await backend().discover(issuer);
  state.discovering = false;
  state.discovery = res.ok ? { issuer, provider: res.provider } : { issuer, error: res.error };
  render();
}

function discoveryFor(issuer) {
  return state.discovery && state.discovery.issuer === issuer.trim() && state.discovery.provider ? state.discovery.provider : null;
}

async function inspectKey() {
  if (!state.secrets.privateKey.trim()) {
    state.keyInfo = null;
    return render();
  }
  const res = await backend().inspectKey(state.secrets.privateKey);
  state.keyInfo = res.ok ? { key: res.key } : { error: res.error };
  render();
}

// --- rendering ------------------------------------------------------------------------

function render() {
  const focused = document.activeElement?.id;
  const scrollY = window.scrollY;
  clear(root);
  const view = state.view === 'result' || state.exchanging ? resultView() : buildView();
  append(root, [topbar(), view]);
  if (focused) document.getElementById(focused)?.focus({ preventScroll: true });
  window.scrollTo(0, scrollY);
}

function renderPreviewOnly() {
  const slot = document.getElementById('preview-slot');
  if (!slot) return render();
  clear(slot);
  append(slot, actionPanel());
}

function updateForm(mutator, { rerender = true } = {}) {
  mutator(state.form);
  saveForm();
  if (rerender) render();
  else renderPreviewOnly();
}

function providerLabel() {
  const issuer = state.form.issuer.trim();
  const preset = ISSUER_PRESETS.find((p) => p.issuer === issuer);
  if (preset) return preset.label.replace(' (npm run mock-op)', '');
  try {
    return issuer ? new URL(issuer).host : 'no provider yet';
  } catch {
    return 'no provider yet';
  }
}

function topbar() {
  return h('header.topbar', {},
    h('div.topbar-inner', {},
      h('a.brand', { href: redirectUri, onclick: (e) => { e.preventDefault(); show('build'); } },
        h('span.brand-mark', {}, icon('lock', 18, { strokeWidth: 2 })),
        h('span.brand-name', 'OIDC Playground'),
      ),
      h('div.topbar-actions', {},
        h('span.pill.pill-accent', {}, h('span.dot'), providerLabel()),
        h('button.btn.btn-ghost.btn-sm', { type: 'button', onclick: resetEverything, title: 'Forget the result, the secrets in this tab and the form' }, icon('reset', 14, { strokeWidth: 2 }), ' Reset'),
      ),
    ),
  );
}

function resetEverything() {
  state.form = structuredClone(DEFAULT_SELECTION);
  state.secrets = { clientSecret: '', privateKey: '' };
  state.result = null;
  state.keyInfo = null;
  state.discovery = null;
  state.startError = null;
  saveForm();
  saveSecrets();
  saveResult();
  saveJson(sessionStorage, PENDING_KEY, null);
  show('build');
  loadDiscovery();
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
        ? h(`a.step.${cls}`, { href: redirectUri, onclick: (e) => { e.preventDefault(); show('build'); } }, content)
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

function field(label, input, { full = false, hint = null } = {}) {
  return h(`div.field${full ? '.field-full' : ''}`, {}, h('label.field-label', { for: input.id }, label), input, hint ? h('p.field-hint', {}, hint) : null);
}

function errorBanner(error, extra = null) {
  return h('div.banner.banner-err', { role: 'alert' },
    icon('alert', 18),
    h('div', {},
      h('div', {}, h('strong', `${error.error || 'error'}`), error.stage ? h('span.muted', ` · during ${error.stage}`) : null),
      h('div', error.error_description || ''),
      error.errors?.length ? h('ul.plain-list', {}, error.errors.map((e) => h('li', e))) : null,
      extra,
    ),
  );
}

// --- build view -------------------------------------------------------------------------

function buildView() {
  const f = state.form;
  return h('main.main', {},
    stepper(1),
    h('div.page-head', {},
      h('h1.page-title', 'Build the authentication request'),
      h('p.page-lead', 'Fill in the provider and your client, pick scopes and claims, press Authorize. Nothing leaves this browser tab except the requests to the provider.'),
    ),
    h('div.columns', {},
      h('section.col-main', {},
        providerCard(),
        scopesCard(f),
        claimsCard(f),
        optionsCard(f),
      ),
      h('aside.col-side#preview-slot', {}, actionPanel()),
    ),
  );
}

function providerCard() {
  const f = state.form;
  const s = state.secrets;
  const provider = discoveryFor(f.issuer);

  let status;
  if (state.discovering) status = h('span.pill', {}, h('span.spinner.spinner-xs'), ' Loading discovery…');
  else if (provider) status = h('span.pill.pill-ok', {}, icon('check', 14, { strokeWidth: 3 }), ' Discovery loaded');
  else if (state.discovery?.error && state.discovery.issuer === f.issuer.trim()) status = h('span.pill.pill-err', {}, icon('alert', 14), ' Discovery failed');
  else status = h('span.pill', 'Discovery not loaded');

  const presetSelect = h('select.input#f-preset', {
    'aria-label': 'Issuer presets',
    onchange: (e) => {
      const preset = ISSUER_PRESETS.find((p) => p.id === e.target.value);
      if (preset) updateForm((st) => { st.issuer = preset.issuer; });
      loadDiscovery();
    },
  },
    h('option', { value: '', selected: !ISSUER_PRESETS.some((p) => p.issuer === f.issuer) }, 'custom issuer…'),
    ISSUER_PRESETS.map((p) => h('option', { value: p.id, selected: p.issuer === f.issuer }, p.label)),
  );

  const issuerInput = h('input.input.mono#f-issuer', {
    type: 'url', value: f.issuer, placeholder: 'https://idp.e2e.itsme.services/v2', autocomplete: 'off', spellcheck: 'false',
    oninput: (e) => updateForm((st) => { st.issuer = e.target.value; }, { rerender: false }),
    onchange: () => loadDiscovery(),
    onkeydown: (e) => { if (e.key === 'Enter') { e.preventDefault(); loadDiscovery(); } },
  });

  const authSelect = h('select.input#f-auth', {
    onchange: (e) => updateForm((st) => { st.clientAuthMethod = e.target.value; }),
  }, CLIENT_AUTH_METHODS.map((m) => h('option', { value: m.id, selected: m.id === f.clientAuthMethod }, m.label)));

  const needsSecret = f.clientAuthMethod.startsWith('client_secret');
  const needsKey = f.clientAuthMethod === 'private_key_jwt';

  const secretField = needsSecret
    ? field('Client secret', h('div.input-row', {},
        h('input.input.mono#f-secret', {
          type: state.showSecret ? 'text' : 'password', value: s.clientSecret, autocomplete: 'off', spellcheck: 'false', placeholder: 'kept in this tab only',
          oninput: (e) => { state.secrets.clientSecret = e.target.value; saveSecrets(); },
        }),
        h('button.btn.btn-ghost.btn-sm', { type: 'button', onclick: () => { state.showSecret = !state.showSecret; render(); }, 'aria-pressed': String(state.showSecret) }, state.showSecret ? 'Hide' : 'Show'),
      ), { hint: 'Stored in sessionStorage — gone when you close the tab.' })
    : null;

  const keyField = field(needsKey ? 'Private key (JWK or PEM)' : 'Private key (JWK or PEM) — optional, to decrypt encrypted responses',
    h('textarea.input.mono.textarea#f-key', {
      rows: 5, spellcheck: 'false', placeholder: needsKey ? '{"kty":"RSA","kid":"…","d":"…", …}  or  -----BEGIN PRIVATE KEY-----' : 'only needed when the provider encrypts the ID token / UserInfo for your client',
      oninput: (e) => { state.secrets.privateKey = e.target.value; saveSecrets(); },
      onchange: () => inspectKey(),
    }, s.privateKey),
    { full: true, hint: ['Signs the client assertion and decrypts JWE responses. The matching ', h('strong', 'public'), ' key must be in the JWKS you host on your public link (the jwks_uri registered at the provider) — never paste the private key anywhere else.'] });

  let keyInfo = null;
  if (state.keyInfo?.key) {
    const k = state.keyInfo.key;
    keyInfo = h('div.note.note-ok', {},
      h('div.row-between', {},
        h('span', {}, icon('check', 14, { strokeWidth: 3 }), ` Key loaded · ${k.kty} · ${k.alg} · kid `, h('code', k.kid)),
        copyButton('Copy public JWK', () => pretty(k.public_jwk), 'btn-xs'),
      ),
      h('p.field-hint', {}, 'Your hosted JWKS must contain this public key with the same kid.'),
    );
  } else if (state.keyInfo?.error) {
    keyInfo = h('div.note.note-err', {}, icon('alert', 14), ` ${state.keyInfo.error.error_description}`);
  }

  let endpoints = null;
  if (provider) {
    const chips = [];
    if (provider.claims_parameter_supported) chips.push('claims parameter');
    if (provider.code_challenge_methods_supported?.includes('S256')) chips.push('PKCE S256');
    if (provider.token_endpoint_auth_methods_supported?.length) chips.push(`auth: ${provider.token_endpoint_auth_methods_supported.join(', ')}`);
    if (provider.id_token_encryption_alg_values_supported?.length) chips.push('encrypted ID tokens');
    endpoints = h('div.stack-sm', {},
      h('div.endpoints', {},
        Object.entries(provider.endpoints).filter(([, v]) => v).map(([k, v]) =>
          h('div.endpoint', {}, h('span.endpoint-key', k), h('span.endpoint-val.mono', { title: v }, v)),
        ),
      ),
      chips.length ? h('div.chips.chips-sm', {}, chips.map((c) => h('span.tag', c))) : null,
    );
  } else if (state.discovery?.error && state.discovery.issuer === f.issuer.trim()) {
    endpoints = errorBanner(state.discovery.error, h('div.banner-actions', {}, h('button.btn.btn-ghost.btn-sm', { type: 'button', onclick: loadDiscovery }, 'Retry')));
  }

  return card('Provider & client', ['Endpoints are read from the discovery document at ', h('code', '<issuer>/.well-known/openid-configuration'), '. The client details are used only for this flow.'],
    [
      h('div.fields', {},
        field('Issuer', h('div.input-row', {}, issuerInput, h('button.btn.btn-ghost.btn-sm', { type: 'button', onclick: loadDiscovery }, 'Load')), { full: true }),
        field('Preset', presetSelect),
        field('Client ID', h('input.input.mono#f-client', {
          type: 'text', value: f.clientId, placeholder: 'the client_id the provider gave you', autocomplete: 'off', spellcheck: 'false',
          oninput: (e) => updateForm((st) => { st.clientId = e.target.value.trim(); }, { rerender: false }),
        })),
        field('Client authentication', authSelect),
        secretField,
        field('Service code (itsme®)', h('input.input.mono#f-service', {
          type: 'text', value: f.serviceCode ?? '', placeholder: 'becomes the service:<code> scope', autocomplete: 'off', spellcheck: 'false',
          oninput: (e) => {
            updateForm((st) => { st.serviceCode = e.target.value.trim(); }, { rerender: false });
            const chip = document.querySelector('[data-scope="service"] .chip-label');
            if (chip) chip.textContent = `service:${state.form.serviceCode || 'SERVICE_CODE'}`;
          },
        })),
        field('Redirect URI', h('div.input-row', {}, h('input.input.mono#f-redirect', { type: 'text', value: redirectUri, readonly: true }), copyButton('Copy', redirectUri, 'btn-sm')), { hint: 'Register this exact URI at the provider.' }),
        keyField,
        keyInfo,
      ),
      endpoints,
    ],
    { id: 'h-provider', right: status });
}

function scopesCard(f) {
  const chips = SCOPES.map((s) => {
    const on = s.locked || !!f.scopes[s.id];
    const label = s.dynamic ? `service:${f.serviceCode || 'SERVICE_CODE'}` : s.id;
    return h('button.chip', {
      type: 'button', 'aria-pressed': String(on), disabled: s.locked, title: s.hint, dataset: { scope: s.id },
      onclick: () => updateForm((st) => { st.scopes[s.id] = !st.scopes[s.id]; }),
    }, s.locked ? icon('lock', 14) : on ? icon('check', 14, { strokeWidth: 3 }) : null, h('span.chip-label', label));
  });
  return card('Scopes', ['Each scope requests a bundle of claims. ', h('code', 'openid'), ' is required for an ID token.'],
    h('div.chips', {}, chips), { id: 'h-scopes' });
}

function claimsCard(f) {
  const selectedCount = Object.values(f.claims).filter(Boolean).length;
  const targets = [['userinfo', 'UserInfo'], ['id_token', 'ID token'], ['both', 'Both']];
  const seg = h('div.seg', { role: 'group', 'aria-label': 'Deliver claims in' },
    targets.map(([id, label]) =>
      h('button.seg-btn', { type: 'button', 'aria-pressed': String(f.target === id), onclick: () => updateForm((st) => { st.target = id; }) }, label),
    ),
  );
  const right = h('div.card-tools', {}, h('span.muted.nowrap', `${selectedCount} selected`), seg);

  const groups = CLAIM_GROUPS.map((group) =>
    h('div.claim-group', {},
      h('div.claim-group-head', {}, h('h3.claim-group-title', group.title), h('span.claim-group-hint.mono', group.hint)),
      h('div.claim-grid', {}, group.claims.map((c) => claimRow(c, f))),
      group.id === 'itsme' ? h('p.field-hint', {}, 'BENationalNumber and BEeidSn are also released by the ', h('code', 'eid'), ' scope.') : null,
    ),
  );

  return card('Claims', ['Request individual claims through the ', h('code', 'claims'), ' parameter. Mark a claim ', h('em', 'essential'), ' when your flow cannot continue without it.'],
    groups, { id: 'h-claims', right });
}

function claimRow(c, f) {
  const on = !!f.claims[c.id];
  const essential = on && !!f.essential[c.id];
  const inputId = `claim-${c.id}`;
  return h(`div.claim${on ? '.is-on' : ''}`, {},
    h('input', { type: 'checkbox', id: inputId, checked: on, onchange: () => updateForm((st) => { st.claims[c.id] = !st.claims[c.id]; }) }),
    h('label.claim-label.mono', { for: inputId, title: c.title }, c.label),
    h('button.ess', {
      type: 'button', 'aria-pressed': String(essential), disabled: !on,
      'aria-label': `${essential ? 'Unmark' : 'Mark'} ${c.label} as essential`,
      onclick: () => updateForm((st) => { st.essential[c.id] = !st.essential[c.id]; }),
    }, 'essential'),
  );
}

function optionsCard(f) {
  const select = (id, value, options, onchange) =>
    h('select.input', { id, onchange }, options.map((o) => h('option', { value: o.value, selected: o.value === value }, o.label)));
  const acrOptions = [...ACR_PRESETS];
  const supported = discoveryFor(f.issuer)?.acr_values_supported || [];
  for (const v of supported) if (!acrOptions.some((o) => o.value === v)) acrOptions.push({ value: v, label: v });
  if (f.acr && !acrOptions.some((o) => o.value === f.acr)) acrOptions.push({ value: f.acr, label: f.acr });

  return card('Request options', ['Optional parameters from OpenID Connect Core §3.1.2.1. Empty fields are left out of the request.'],
    h('div.fields.fields-3', {},
      field('acr_values', select('f-acr', f.acr, acrOptions, (e) => updateForm((st) => { st.acr = e.target.value; }))),
      field('prompt', select('f-prompt', f.prompt, [
        { value: '', label: 'not set' }, { value: 'none', label: 'none' }, { value: 'login', label: 'login' }, { value: 'consent', label: 'consent' }, { value: 'select_account', label: 'select_account' },
      ], (e) => updateForm((st) => { st.prompt = e.target.value; }))),
      field('ui_locales', select('f-locales', f.uiLocales, [
        { value: '', label: 'not set' }, { value: 'nl', label: 'nl' }, { value: 'fr', label: 'fr' }, { value: 'de', label: 'de' }, { value: 'en', label: 'en' },
      ], (e) => updateForm((st) => { st.uiLocales = e.target.value; }))),
      field('max_age (seconds)', h('input.input.mono#f-maxage', { type: 'number', min: 0, value: f.maxAge, placeholder: 'e.g. 300', oninput: (e) => updateForm((st) => { st.maxAge = e.target.value; }, { rerender: false }) })),
      field('login_hint', h('input.input.mono#f-hint', { type: 'text', value: f.loginHint, placeholder: 'phone number or e-mail', autocomplete: 'off', oninput: (e) => updateForm((st) => { st.loginHint = e.target.value; }, { rerender: false }) })),
      h('div.field.field-check', {},
        h('input', { type: 'checkbox', id: 'f-pkce', checked: f.pkce, onchange: () => updateForm((st) => { st.pkce = !st.pkce; }) }),
        h('label.field-label', { for: 'f-pkce' }, 'PKCE ', h('span.muted', '(S256 code challenge)')),
      ),
    ),
    { id: 'h-options' });
}

function actionPanel() {
  const f = state.form;
  const provider = discoveryFor(f.issuer);
  const body = buildStartRequest(f, f.serviceCode);
  const problems = readinessProblems();
  const claimCount = requestedClaimKeys(body.claims).length;
  const authLabel = CLIENT_AUTH_METHODS.find((m) => m.id === f.clientAuthMethod)?.id || f.clientAuthMethod;

  const summary = kvRows([
    { k: 'provider', v: provider ? provider.issuer : f.issuer.trim() || '—' },
    { k: 'client_id', v: f.clientId || '—' },
    { k: 'auth', v: authLabel },
    { k: 'scope', v: body.scopes.join(' ') },
    { k: 'claims', v: claimCount ? `${claimCount} individual claim${claimCount === 1 ? '' : 's'} → ${Object.keys(body.claims).join(' + ')}` : 'none (scopes only)' },
    { k: 'pkce', v: body.pkce ? 'S256' : 'off' },
  ], { keyWidth: 'minmax(80px, 100px)' });

  const modeSelect = h('select.input#f-mode', {
    onchange: (e) => { updateForm((st) => { st.mode = e.target.value; }); if (f.issuer) loadDiscovery(); },
  },
    h('option', { value: 'direct', selected: f.mode === 'direct' }, 'this browser (provider must allow CORS)'),
    h('option', { value: 'helper', selected: f.mode === 'helper' }, 'local helper (npm start)'),
  );

  return [
    card('Ready to authorize', 'What will be sent, in short.', [
      summary,
      h('div.fields', {},
        field('Exchange the code through', modeSelect, { full: true }),
        f.mode === 'helper'
          ? field('Helper URL', h('input.input.mono#f-helper', {
              type: 'url', value: f.helperUrl, placeholder: 'http://localhost:3000', spellcheck: 'false',
              oninput: (e) => updateForm((st) => { st.helperUrl = e.target.value.trim(); }, { rerender: false }),
              onchange: () => { if (f.issuer) loadDiscovery(); },
            }), { full: true, hint: 'Run "npm start" from the repo; it does discovery, the token exchange and UserInfo for providers that block cross-origin requests.' })
          : null,
      ),
      h('div.cta', {},
        h('button.btn.btn-primary.btn-lg', { type: 'button', disabled: problems.length > 0 || state.starting, onclick: startAuthorization },
          state.starting ? 'Redirecting…' : `Authorize with ${providerLabel().split('·')[0].trim()}`, icon('arrow', 18)),
        problems.length ? h('ul.plain-list.muted.small', {}, problems.map((p) => h('li', p))) : null,
        state.startError ? errorBanner(state.startError) : null,
        h('p.cta-note', {}, 'You leave for the provider and come back to this page with a one-time code. state, nonce and the PKCE verifier are generated here and kept in this tab.'),
      ),
    ], { id: 'h-ready' }),
  ];
}

function readinessProblems() {
  const f = state.form;
  const problems = [];
  if (!f.issuer.trim()) problems.push('Enter the issuer.');
  else if (!discoveryFor(f.issuer)) problems.push('Load the discovery document first.');
  if (!f.clientId.trim()) problems.push('Enter the client ID.');
  if (f.clientAuthMethod.startsWith('client_secret') && !state.secrets.clientSecret) problems.push('Enter the client secret.');
  if (f.clientAuthMethod === 'private_key_jwt' && !state.secrets.privateKey.trim()) problems.push('Paste the private key for private_key_jwt.');
  if (f.mode === 'helper' && !/^https?:\/\//.test(f.helperUrl)) problems.push('Enter the helper URL.');
  if (!window.isSecureContext || !crypto.subtle) problems.push('Open the page over https or on localhost (needed to generate PKCE).');
  return problems;
}

// --- starting the flow (all in the browser) -------------------------------------------------

function randomUrlSafe(bytes = 32) {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return base64url(buf);
}

function base64url(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function pkcePair() {
  const verifier = randomUrlSafe(32); // 43 characters, RFC 7636
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return { verifier, challenge: base64url(new Uint8Array(digest)) };
}

async function startAuthorization() {
  const f = state.form;
  const provider = discoveryFor(f.issuer);
  if (!provider) return;
  state.starting = true;
  state.startError = null;
  renderPreviewOnly();
  try {
    const body = buildStartRequest(f, f.serviceCode);
    const stateValue = randomUrlSafe(24);
    const nonce = randomUrlSafe(24);
    const pkce = body.pkce ? await pkcePair() : null;
    const params = buildAuthorizationParams(body, { clientId: f.clientId.trim(), redirectUri, state: stateValue, nonce, codeChallenge: pkce?.challenge });
    const url = new URL(provider.endpoints.authorization_endpoint);
    for (const [k, v] of params) url.searchParams.set(k, v);

    saveJson(sessionStorage, PENDING_KEY, {
      startedAt: new Date().toISOString(),
      issuer: f.issuer.trim(),
      clientId: f.clientId.trim(),
      clientAuthMethod: f.clientAuthMethod,
      mode: f.mode,
      helperUrl: f.helperUrl,
      redirectUri,
      state: stateValue,
      nonce,
      codeVerifier: pkce?.verifier || null,
      maxAge: body.max_age ?? null,
      request: {
        url: url.href,
        endpoint: provider.endpoints.authorization_endpoint,
        params: params.map(([k, v]) => ({ k, v })),
        scopes: body.scopes,
        claims: body.claims,
        redirectUri,
      },
      endpoints: provider.endpoints,
    });
    state.result = null;
    saveResult();
    window.location.assign(url.href);
  } catch (err) {
    state.starting = false;
    state.startError = { error: 'start_failed', error_description: err.message };
    renderPreviewOnly();
  }
}

// --- back from the provider: finish the flow -------------------------------------------------

async function handleCallback() {
  const query = Object.fromEntries(new URLSearchParams(location.search));
  const callbackUrl = location.href;
  const pending = loadJson(sessionStorage, PENDING_KEY, null);
  saveJson(sessionStorage, PENDING_KEY, null);
  const callback = { url: `${location.pathname}${location.search}`, query, receivedAt: new Date().toISOString() };
  history.replaceState({}, '', location.pathname); // the one-time code must not stay in the address bar

  state.exchanging = true;
  render();

  const finish = (result) => {
    state.result = result;
    state.exchanging = false;
    state.tab = 'claims';
    state.userinfoTab = 'plain';
    saveResult();
    show('result');
  };

  if (!pending) {
    return finish({
      status: 'error',
      callback,
      error: {
        stage: 'callback',
        error: 'no_pending_request',
        error_description: 'This tab has no request waiting for a callback (it was started in another tab, already used, or the tab was closed). Start a new request.',
      },
    });
  }
  if (query.state && query.state !== pending.state) {
    return finish({ status: 'error', callback, request: pending.request, config: configSummary(pending), error: { stage: 'callback', error: 'state_mismatch', error_description: `The state in the callback (${query.state}) is not the one this tab sent (${pending.state}).` } });
  }
  if (query.error) {
    return finish({ status: 'error', callback, request: pending.request, config: configSummary(pending), error: { stage: 'authorization', error: query.error, error_description: query.error_description || 'The provider returned an error instead of a code.' } });
  }

  const secrets = state.secrets;
  const clientAuth = { method: pending.clientAuthMethod };
  if (pending.clientAuthMethod.startsWith('client_secret')) clientAuth.client_secret = secrets.clientSecret;
  if (secrets.privateKey.trim()) clientAuth.private_key = secrets.privateKey;

  const res = await backendFor({ mode: pending.mode, helperUrl: pending.helperUrl }).token({
    issuer: pending.issuer,
    client_id: pending.clientId,
    client_auth: clientAuth,
    callback_url: callbackUrl,
    redirect_uri: pending.redirectUri || redirectUri,
    expected_state: pending.state,
    expected_nonce: pending.nonce,
    code_verifier: pending.codeVerifier || undefined,
    max_age: pending.maxAge ?? undefined,
  });

  if (!res.ok) {
    return finish({ status: 'error', callback, request: pending.request, config: configSummary(pending), error: res.error });
  }
  finish({
    status: 'ok',
    callback,
    request: pending.request,
    config: configSummary(pending),
    endpoints: { ...pending.endpoints, ...(res.endpoints || {}) },
    tokens: res.tokens,
    idToken: res.idToken,
    userinfo: null,
  });
}

function configSummary(pending) {
  return { issuer: pending.issuer, clientId: pending.clientId, clientAuthMethod: pending.clientAuthMethod, mode: pending.mode || 'direct', helperUrl: pending.helperUrl };
}

// --- result view -------------------------------------------------------------------------

function resultView() {
  const r = state.result;
  if (state.exchanging) {
    return h('main.main', {}, stepper(3), h('div.card.card-center', {}, h('div.spinner'), h('p.muted', 'Exchanging the code for tokens and validating the ID token…')));
  }
  if (!r) {
    return h('main.main', {}, stepper(1),
      h('div.card.card-center', {},
        h('h1.page-title', 'Nothing here yet'),
        h('p.muted', 'This tab has no completed authorization. Build a request and authorize to see tokens and claims.'),
        h('a.btn.btn-primary', { href: redirectUri, onclick: (e) => { e.preventDefault(); show('build'); } }, 'Build a request', icon('arrow', 18)),
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
      h('p.page-lead', `${r.config.issuer} · client ${r.config.clientId} · ${r.config.clientAuthMethod} · exchanged ${r.config.mode === 'helper' ? 'through the local helper' : 'in this browser'}. Below is everything the ID token says — about the user and about itself.`),
    ),
    h('div.columns', {},
      h('section.col-main', {}, idTokenCard(r), userinfoCard(r)),
      h('aside.col-side', {}, tokenResponseCard(r), checksCard('ID token checks', 'OpenID Connect Core §3.1.3.7', r.idToken.checks, 'h-checks'), requestSentCard(r)),
    ),
    h('div.actions', {},
      h('a.btn.btn-primary.btn-lg', { href: redirectUri, onclick: (e) => { e.preventDefault(); show('build'); } }, icon('reset', 16, { strokeWidth: 2 }), 'Start a new request'),
      copyButton('Copy result as JSON', () => pretty(r)),
    ),
  );
}

function errorView(r) {
  const e = r.error || {};
  const lead = e.stage === 'authorization'
    ? 'The provider sent back an error instead of an authorization code.'
    : e.stage === 'callback'
      ? 'The provider sent us back, but this tab was not waiting for it.'
      : 'The authorization code could not be exchanged, or the ID token failed validation.';
  return h('main.main', {},
    stepper(e.stage === 'authorization' || e.stage === 'callback' ? 2 : 3),
    errorBanner(e, r.callback?.url ? h('code.mono.small.break', r.callback.url) : null),
    h('div.page-head', {}, h('h1.page-title', 'The flow did not complete'), h('p.page-lead', lead)),
    h('div.columns', {},
      h('section.col-main', {}, r.request ? requestSentCard(r, { open: true }) : null),
      h('aside.col-side', {}, r.callback?.query && Object.keys(r.callback.query).length ? card('Callback parameters', null, kvRows(Object.entries(r.callback.query).map(([k, v]) => ({ k, v }))), { id: 'h-cbq' }) : null),
    ),
    h('div.actions', {},
      h('a.btn.btn-primary.btn-lg', { href: redirectUri, onclick: (ev) => { ev.preventDefault(); show('build'); } }, icon('reset', 16, { strokeWidth: 2 }), 'Back to the request builder'),
    ),
  );
}

function tabs(items, current, onPick) {
  return h('div.tabs', { role: 'tablist' },
    items.map(([id, label]) => h('button.tab', { type: 'button', role: 'tab', 'aria-selected': String(current === id), onclick: () => onPick(id) }, label)),
  );
}

function idTokenCard(r) {
  const { header, format, checks } = r.idToken;
  const allOk = checks.every((c) => c.ok);
  const right = h(`span.pill.${allOk ? 'pill-ok' : 'pill-err'}`, {}, icon(allOk ? 'check' : 'alert', 14, { strokeWidth: 3 }), allOk ? ' Valid' : ' Check failed');
  const subtitle = format === 'jwe'
    ? ['Encrypted JWT (JWE) · ', h('code', `${header?.alg} / ${header?.enc}`), ' · decrypted with your private key']
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
  const requestedIdToken = Object.keys(r.request?.claims?.id_token || {});
  const essential = new Set(Object.entries(r.request?.claims?.id_token || {}).filter(([, v]) => v?.essential).map(([k]) => k));

  const userKeys = Object.keys(payload).filter((k) => !TOKEN_CLAIMS.includes(k));
  const missing = requestedIdToken.filter((k) => !(k in payload));
  const rows = [
    ...userKeys.map((k) => ({ key: k, value: payload[k], missing: false })),
    ...missing.map((k) => ({ key: k, value: undefined, missing: true })),
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
      rows.length ? claimsTable(rows, { essential }) : h('p.muted', 'The ID token carries no user claims; request some for the ID token, or look at UserInfo.'),
    ),
    h('div.stack-sm', {}, h('h3.subhead', 'About the token'), kvRows(tokenRows, { keyWidth: 'minmax(100px, 140px)' })),
  );
}

function claimsTable(rows, { essential = new Set() } = {}) {
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
        ? ['The token was decrypted with the pasted private key; the nested JWS signature was verified against the provider’s ', h('code', 'jwks_uri'), '.']
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
    h('div.endpoint-box.mono', r.endpoints?.token_endpoint || 'token endpoint'),
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
  return h('section.card', {},
    h('details.details', { open: open || null },
      h('summary.details-summary', {}, 'Request sent', h('span.muted', ` · ${req.params.length} parameters`)),
      h('div.stack-sm', {},
        h('div.endpoint-box.mono.break', req.endpoint),
        kvRows(req.params, { keyWidth: 'minmax(110px, 170px)' }),
        copyButton('Copy full URL', req.url, 'btn-sm'),
      ),
    ),
  );
}

function userinfoCard(r) {
  const ui = r.userinfo;
  const endpoint = r.endpoints?.userinfo_endpoint || 'userinfo endpoint';

  if (!ui) {
    return card('UserInfo', ['Call the ', h('code', 'userinfo_endpoint'), ' with the access token and see the plain values the provider returns.'],
      h('div.cta.cta-inline', {},
        h('div.endpoint-box.mono', `GET ${endpoint}`),
        h('button.btn.btn-primary.btn-lg', { type: 'button', disabled: state.userinfoBusy, onclick: callUserinfo },
          state.userinfoBusy ? 'Calling userinfo…' : 'Call the userinfo endpoint', icon('arrow', 18)),
        state.userinfoError ? errorBanner(state.userinfoError) : null,
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
      errorBanner(ui.error),
      ui.response.body ? h('pre.code', ui.response.body) : null,
      h('button.btn.btn-ghost', { type: 'button', onclick: callUserinfo }, 'Try again'),
    ], { id: 'h-userinfo', right: statusTag });
  }

  const claims = ui.claims || {};
  const requestedUserinfo = Object.keys(r.request?.claims?.userinfo || {});
  const essential = new Set(Object.entries(r.request?.claims?.userinfo || {}).filter(([, v]) => v?.essential).map(([k]) => k));
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

  const panel = state.userinfoTab === 'raw' ? h('pre.code', ui.response.body) : claimsTable(rows, { essential });
  const formatLabel = ui.format === 'json' ? 'application/json' : ui.format === 'jwt' ? 'signed JWT (verified)' : 'encrypted JWT (decrypted + verified)';

  return card('UserInfo', [`${Object.keys(claims).length} claims · `, h('code', formatLabel)], [
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
  const r = state.result;
  if (!r || r.status !== 'ok') return;
  state.userinfoBusy = true;
  state.userinfoError = null;
  render();
  const res = await backendFor({ mode: r.config.mode, helperUrl: r.config.helperUrl }).userinfo({
    issuer: r.config.issuer,
    client_id: r.config.clientId,
    access_token: r.tokens.access_token,
    expected_sub: r.idToken.payload.sub,
    private_key: state.secrets.privateKey.trim() || undefined,
  });
  state.userinfoBusy = false;
  if (!res.ok) {
    state.userinfoError = res.error;
  } else {
    r.userinfo = res.userinfo;
    state.userinfoTab = 'plain';
    saveResult();
  }
  render();
}

// a little hook for debugging in the console
window.__oidcPlayground = { state, redirectUri };
