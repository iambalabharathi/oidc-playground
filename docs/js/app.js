// A static page (GitHub Pages friendly). By default it only builds the authorization
// request and opens it: no key, no secret and no server are involved. Exchanging the code
// is optional (section "Code exchange"): in the browser (oauth4webapi) for providers that
// allow CORS, or through a helper that speaks the same four calls.
import { h, append, clear, icon, formatTime, formatIso, pretty, copyButton, truncateMiddle } from './ui.js';
import { backendFor } from './backends.js';
import {
  SCOPES, CLAIM_GROUPS, DEFAULT_SELECTION, TOKEN_CLAIMS, ISSUER_PRESETS, CLIENT_AUTH_METHODS, ASSERTION_AUDIENCES, CUSTOM_CLAIM_ID_PREFIX,
  buildStartRequest, buildAuthorizationParams, parseExtraParams, claimLabel, shortClaimName, allClaims, standardClaimByKey,
} from './catalog.js';

const FORM_KEY = 'oidc-playground.form.v2'; // localStorage: everything that is not a secret
const SECRETS_KEY = 'oidc-playground.secrets.v2'; // sessionStorage: client secret, private key (this tab only)
const PENDING_KEY = 'oidc-playground.pending.v2'; // sessionStorage: what we must remember across the redirect
const RESULT_KEY = 'oidc-playground.result.v2'; // sessionStorage: the last result, so a reload keeps it
const VIEW_KEY = 'oidc-playground.view.v2'; // sessionStorage: which view a reload comes back to
const SENT_KEY = 'oidc-playground.sent.v1'; // localStorage: state of the last request opened in a new tab (no nonce, no verifier)
const STEPS = ['Build request', 'Authorize', 'Tokens & claims', 'UserInfo'];

const state = {
  form: loadJson(localStorage, FORM_KEY, structuredClone(DEFAULT_SELECTION)),
  secrets: loadJson(sessionStorage, SECRETS_KEY, { clientSecret: '', privateKey: '', keySource: null }),
  discovery: null, // { issuer, provider } | { issuer, error }
  discovering: false,
  keyInfo: null, // { key } | { error }
  keyLoading: false, // fetching the private key from its URL
  showSecret: false,
  starting: false,
  startError: null,
  callbackPasteError: null, // when a pasted callback URL cannot be used
  openSections: {}, // collapsible sections the user opened (by heading id)
  painted: false, // the current view has been drawn once (entrance animation only on the first paint)
  lastToggled: null, // claim id whose checkbox was just clicked (only that one animates)
  urlParts: null, // query parameters of the last shown authorization URL, to flash what changed
  draft: null, // { state, nonce, verifier, challenge } for the request being built, so the URL can be shown before submitting
  openedAt: null, // when the current request was last opened in a new tab
  result: loadJson(sessionStorage, RESULT_KEY, null),
  view: sessionStorage.getItem(VIEW_KEY) === 'result' ? 'result' : 'build',
  exchanging: false,
  userinfoBusy: false,
  userinfoError: null,
  tab: 'claims',
  userinfoTab: 'plain',
};

const root = document.getElementById('app');
const seenHeadings = new Set(); // ids of section headings whose underline has already been drawn
let headingObserver = null;
// The page itself is the default redirect URI: on GitHub Pages that is https://<user>.github.io/<repo>/
const pageUrl = `${location.origin}${location.pathname}`;
/** The redirect URI in use: the page, unless the client is registered with another one. */
const redirectUriFor = (f = state.form) => (f.redirectUri || '').trim() || pageUrl;
const backend = () => backendFor(state.form);
/** True when the page also redeems the code; otherwise it only builds and opens the request. */
const exchanges = (f = state.form) => f.mode === 'direct' || f.mode === 'helper';

// Building the request is the default. An exchange mode is only kept when the user picked it.
if (!state.form.modeChosen || !['request', 'direct', 'helper'].includes(state.form.mode)) state.form.mode = 'request';

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
  state.painted = false;
  saveView();
  render();
  window.scrollTo(0, 0);
  if (view === 'build') newDraft(); // a fresh state / nonce / PKCE pair for the next request
}

async function boot() {
  render();
  if (isCallback()) return handleCallback();
  const tasks = [newDraft()];
  if (state.form.issuer) tasks.push(loadDiscovery());
  if (exchanges()) tasks.push(loadKey());
  await Promise.all(tasks);
}

/** The key is only needed to redeem a code: inspect the one in this tab, or fetch it from its URL. */
function loadKey() {
  if (state.secrets.privateKey.trim()) return inspectKey();
  if (state.form.keyUrl) return fetchKeyFromUrl();
  return null;
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

/** Loads the private key (JWK, private JWKS or PEM) from the configured URL into this tab's sessionStorage. */
async function fetchKeyFromUrl({ silent = false } = {}) {
  const url = (state.form.keyUrl || '').trim();
  if (!url) return false;
  state.keyLoading = true;
  if (!silent) render();
  try {
    const res = await fetch(url, { cache: 'no-store', credentials: 'omit' });
    if (!res.ok) throw new Error(`HTTP ${res.status}${res.statusText ? ` ${res.statusText}` : ''}`);
    const text = (await res.text()).trim();
    if (!text) throw new Error('the response was empty');
    state.secrets.privateKey = text;
    state.secrets.keySource = { url, fetchedAt: new Date().toISOString() };
    saveSecrets();
    state.keyLoading = false;
    await inspectKey();
    return true;
  } catch (err) {
    state.keyLoading = false;
    state.keyInfo = {
      error: {
        error: 'key_fetch_failed',
        error_description: `Could not load the key from ${url}: ${err.message}. The URL must be reachable from this browser and allow cross-origin requests (CORS); otherwise paste the key below.`,
      },
    };
    if (!silent) render();
    return false;
  }
}

// --- rendering ------------------------------------------------------------------------

function render() {
  const focused = document.activeElement?.id;
  const scrollY = window.scrollY;
  clear(root);
  const view = state.view === 'result' || state.exchanging ? resultView() : buildView();
  if (!state.painted) view.classList.add('enter');
  append(root, [topbar(), view]);
  state.painted = true;
  state.lastToggled = null;
  observeHeadings();
  if (focused) document.getElementById(focused)?.focus({ preventScroll: true });
  window.scrollTo(0, scrollY);
}

// Section headings draw their underline the first time they scroll into view; a heading
// already seen gets the finished underline on later re-renders instead of replaying it.
function observeHeadings() {
  const titles = document.querySelectorAll('.card-title:not(.is-seen)');
  if (!titles.length) return;
  if (!('IntersectionObserver' in window)) {
    titles.forEach((t) => t.classList.add('is-seen', 'no-anim'));
    return;
  }
  headingObserver ||= new IntersectionObserver((entries) => {
    for (const e of entries) {
      if (!e.isIntersecting) continue;
      e.target.classList.add('is-seen');
      if (e.target.id) seenHeadings.add(e.target.id);
      headingObserver.unobserve(e.target);
    }
  }, { threshold: 0.5 });
  titles.forEach((t) => {
    if (t.id && seenHeadings.has(t.id)) t.classList.add('is-seen', 'no-anim');
    else headingObserver.observe(t);
  });
}

function renderPreviewOnly() {
  const slot = document.getElementById('submit-slot');
  if (!slot) return render();
  clear(slot);
  append(slot, [submitCard()]);
  observeHeadings();
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
  if (preset) return preset.label;
  try {
    return issuer ? new URL(issuer).host : 'no provider yet';
  } catch {
    return 'no provider yet';
  }
}

function topbar() {
  return h('header.topbar', {},
    h('div.topbar-inner', {},
      h('a.brand', { href: pageUrl, onclick: (e) => { e.preventDefault(); show('build'); } },
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
  state.secrets = { clientSecret: '', privateKey: '', keySource: null };
  state.result = null;
  state.keyInfo = null;
  state.discovery = null;
  state.startError = null;
  saveForm();
  saveSecrets();
  saveResult();
  saveJson(sessionStorage, PENDING_KEY, null);
  saveJson(localStorage, SENT_KEY, null);
  state.openedAt = null;
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
        ? h(`a.step.${cls}`, { href: pageUrl, onclick: (e) => { e.preventDefault(); show('build'); } }, content)
        : h(`div.step${cls ? '.' + cls : ''}`, { 'aria-current': n === current ? 'step' : null }, content),
    );
    if (i < STEPS.length - 1) items.push(h('span.step-sep', {}, icon('chevron', 16, { strokeWidth: 2 })));
  });
  return h('nav.stepper', { 'aria-label': 'Flow steps' }, items);
}

function card(title, subtitle, children, { id, right, extraClass = '', collapsible = false, summary = null, defaultOpen = false } = {}) {
  const open = !collapsible || (state.openSections[id] ?? defaultOpen);
  const toggle = () => { state.openSections[id] = !open; render(); };
  const head = h(`div.card-head${collapsible ? '.is-clickable' : ''}`, collapsible ? { onclick: (e) => { if (!e.target.closest('button, a, input, select, label')) toggle(); } } : {},
    h('div.card-title-wrap', {},
      h('h2.card-title', { id }, title),
      subtitle ? h('p.card-subtitle', {}, subtitle) : null,
      collapsible && !open && summary ? h('p.card-subtitle.card-summary', {}, summary) : null,
    ),
    right || null,
    collapsible
      ? h('button.btn.btn-ghost.btn-sm.card-toggle', { type: 'button', 'aria-expanded': String(open), 'aria-controls': `${id}-body`, onclick: toggle }, open ? 'Hide' : 'Edit', icon('chevron', 14, { strokeWidth: 2.2 }))
      : null,
  );
  const body = h('div.card-body', { id: collapsible ? `${id}-body` : null }, children);
  const cls = `section.card${extraClass ? '.' + extraClass : ''}${collapsible ? (open ? '.is-open' : '.is-collapsed') : ''}`;
  return h(cls, { 'aria-labelledby': id }, head, collapsible ? h('div.card-fold', {}, body) : body);
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
      error.body ? h('details.details', {}, h('summary.details-summary', 'Provider response'), h('pre.url-text', {}, pretty(error.body))) : null,
      extra,
    ),
  );
}

// --- build view -------------------------------------------------------------------------

function buildView() {
  const f = state.form;
  return h('main.main.build', {},
    h('div.intro', {},
      exchanges(f) ? stepper(1) : null,
      h('div.page-head', {}, h('h1.page-title', 'Build the authentication request')),
    ),
    pendingCard(),
    h('div.form-stack', {},
      providerCard(),
      scopesCard(f),
      claimsCard(f),
      optionsCard(f),
      exchangeCard(f),
      h('div#submit-slot', {}, submitCard()),
    ),
  );
}

function providerCard() {
  const f = state.form;
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
      if (preset) updateForm((st) => { st.issuer = preset.issuer; if (preset.keyUrl) st.keyUrl = preset.keyUrl; });
      loadDiscovery();
      if (preset?.keyUrl) fetchKeyFromUrl();
    },
  },
    h('option', { value: '', selected: !ISSUER_PRESETS.some((p) => p.issuer === f.issuer) }, 'custom issuer…'),
    ISSUER_PRESETS.map((p) => h('option', { value: p.id, selected: p.issuer === f.issuer }, p.label)),
  );

  const issuerInput = h('input.input.mono#f-issuer', {
    type: 'url', value: f.issuer, placeholder: 'https://issuer.example.com', autocomplete: 'off', spellcheck: 'false',
    oninput: (e) => updateForm((st) => { st.issuer = e.target.value; }, { rerender: false }),
    onchange: () => loadDiscovery(),
    onkeydown: (e) => { if (e.key === 'Enter') { e.preventDefault(); loadDiscovery(); } },
  });

  const customRedirect = redirectUriFor(f) !== pageUrl;

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

  return card('Provider & client', null,
    [
      h('div.fields', {},
        field('Issuer', h('div.input-row', {}, issuerInput, h('button.btn.btn-ghost.btn-sm', { type: 'button', onclick: loadDiscovery }, 'Load')), { full: true }),
        ISSUER_PRESETS.length ? field('Preset', presetSelect) : null,
        field('Client ID', h('input.input.mono#f-client', {
          type: 'text', value: f.clientId, placeholder: 'the client_id the provider gave you', autocomplete: 'off', spellcheck: 'false',
          oninput: (e) => updateForm((st) => { st.clientId = e.target.value.trim(); }, { rerender: false }),
        })),
        field('Redirect URI', h('div.input-row', {},
          h('input.input.mono#f-redirect', {
            type: 'url', value: f.redirectUri || pageUrl, placeholder: pageUrl, autocomplete: 'off', spellcheck: 'false',
            oninput: (e) => updateForm((st) => { const v = e.target.value.trim(); st.redirectUri = v === pageUrl ? '' : v; }, { rerender: false }),
            onchange: () => render(),
          }),
          copyButton('Copy', () => redirectUriFor(state.form), 'btn-sm'),
          customRedirect ? h('button.btn.btn-ghost.btn-sm', { type: 'button', onclick: () => updateForm((st) => { st.redirectUri = ''; }) }, 'Use this page') : null,
        ), { full: true, hint: !customRedirect
          ? 'Register this exact URI at the provider, or type the one your client is registered with.'
          : exchanges(f)
            ? ['The provider sends the browser there, not here. Copy the complete URL you land on and paste it into ', h('strong', 'Finish the request'), ' at the top of this page.']
            : 'The provider sends the browser to this address after sign-in.' }),
      ),
      endpoints,
    ],
    { id: 'h-provider', right: status });
}

function scopesCard(f) {
  const chips = SCOPES.map((s) => {
    const on = s.locked || !!f.scopes[s.id];
    return h('button.chip', {
      type: 'button', 'aria-pressed': String(on), disabled: s.locked, title: s.hint, dataset: { scope: s.id },
      onclick: () => updateForm((st) => { st.scopes[s.id] = !st.scopes[s.id]; }),
    }, s.locked ? icon('lock', 14) : on ? icon('check', 14, { strokeWidth: 3 }) : null, h('span.chip-label', s.id));
  });
  const extra = field('Additional scopes', h('input.input.mono#f-extra-scopes', {
    type: 'text', value: f.extraScopes ?? '', placeholder: 'provider-specific scopes, space-separated', autocomplete: 'off', spellcheck: 'false',
    oninput: (e) => updateForm((st) => { st.extraScopes = e.target.value; }, { rerender: false }),
  }), { full: true, hint: 'Sent as typed, after the standard scopes.' });
  return card('Scopes', null,
    [h('div.chips', {}, chips), h('div.fields', {}, extra)], { id: 'h-scopes' });
}

function claimsCard(f) {
  const selectedCount = allClaims(f).filter((c) => f.claims[c.id]).length;
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
    ),
  );

  const custom = allClaims(f).filter((c) => c.custom);
  const customGroup = h('div.claim-group', {},
    h('div.claim-group-head', {}, h('h3.claim-group-title', 'Custom claims'), h('span.claim-group-hint.mono', 'provider-specific · any claim name or URI')),
    custom.length ? h('div.claim-grid', {}, custom.map((c) => claimRow(c, f, { onremove: () => removeCustomClaim(c) }))) : null,
    h('div.input-row', {},
      h('input.input.mono#f-custom-claim', {
        type: 'text', placeholder: 'e.g. https://example.com/claims/employee_id', autocomplete: 'off', spellcheck: 'false', 'aria-label': 'Custom claim name or URI',
        onkeydown: (e) => { if (e.key === 'Enter') { e.preventDefault(); addCustomClaim(e.target.value); } },
      }),
      h('button.btn.btn-ghost.btn-sm', { type: 'button', onclick: () => addCustomClaim(document.getElementById('f-custom-claim')?.value) }, 'Add'),
    ),
  );

  return card('Claims', null,
    [...groups, customGroup], { id: 'h-claims', right });
}

function addCustomClaim(raw) {
  const key = String(raw || '').trim();
  if (!key) return;
  updateForm((st) => {
    const standard = standardClaimByKey(key);
    if (standard) { st.claims[standard.id] = true; return; }
    st.customClaims = st.customClaims || [];
    if (!st.customClaims.includes(key)) st.customClaims.push(key);
    st.claims[CUSTOM_CLAIM_ID_PREFIX + key] = true;
  });
}

function removeCustomClaim(c) {
  updateForm((st) => {
    st.customClaims = (st.customClaims || []).filter((k) => k !== c.key);
    delete st.claims[c.id];
    delete st.essential[c.id];
  });
}

function claimRow(c, f, { onremove = null } = {}) {
  const on = !!f.claims[c.id];
  const essential = on && !!f.essential[c.id];
  const inputId = `claim-${c.id}`;
  return h(`div.claim${on ? '.is-on' : ''}${state.lastToggled === c.id ? '.just-toggled' : ''}`, {},
    h('input', { type: 'checkbox', id: inputId, checked: on, onchange: () => { state.lastToggled = c.id; updateForm((st) => { st.claims[c.id] = !st.claims[c.id]; }); } }),
    h('label.claim-label.mono', { for: inputId, title: c.title }, c.label),
    h('button.ess', {
      type: 'button', 'aria-pressed': String(essential), disabled: !on,
      'aria-label': `${essential ? 'Unmark' : 'Mark'} ${c.label} as essential`,
      onclick: () => updateForm((st) => { st.essential[c.id] = !st.essential[c.id]; }),
    }, 'essential'),
    onremove ? h('button.btn.btn-ghost.btn-xs', { type: 'button', 'aria-label': `Remove ${c.label}`, title: 'Remove this claim', onclick: onremove }, '×') : null,
  );
}

function optionsCard(f) {
  const select = (id, value, options, onchange) =>
    h('select.input', { id, onchange }, options.map((o) => h('option', { value: o.value, selected: o.value === value }, o.label)));
  const supportedAcr = discoveryFor(f.issuer)?.acr_values_supported || [];
  const acrInput = h('input.input.mono#f-acr', {
    type: 'text', value: f.acr, list: 'acr-values-list', placeholder: 'provider default', autocomplete: 'off', spellcheck: 'false',
    oninput: (e) => updateForm((st) => { st.acr = e.target.value.trim(); }, { rerender: false }),
  });

  const setOptions = [['acr_values', f.acr], ['prompt', f.prompt], ['ui_locales', f.uiLocales], ['max_age', f.maxAge], ['login_hint', f.loginHint]]
    .filter(([, v]) => v !== '' && v !== null && v !== undefined).map(([k]) => k);
  const extraCount = parseExtraParams(f.extraParams).length;
  const summary = `${setOptions.length ? setOptions.join(', ') : 'none set'} · PKCE ${f.pkce ? 'on' : 'off'}${extraCount ? ` · ${extraCount} extra parameter${extraCount === 1 ? '' : 's'}` : ''}`;
  return card('Request options', null,
    h('div.fields.fields-3', {},
      field('acr_values', acrInput, { hint: supportedAcr.length ? 'Suggestions come from acr_values_supported.' : null }),
      h('datalist#acr-values-list', {}, supportedAcr.map((v) => h('option', { value: v }))),
      field('prompt', select('f-prompt', f.prompt, [
        { value: '', label: 'not set' }, { value: 'none', label: 'none' }, { value: 'login', label: 'login' }, { value: 'consent', label: 'consent' }, { value: 'select_account', label: 'select_account' },
      ], (e) => updateForm((st) => { st.prompt = e.target.value; }))),
      field('ui_locales', h('input.input.mono#f-locales', { type: 'text', value: f.uiLocales, placeholder: 'e.g. en or fr-CA fr en', autocomplete: 'off', spellcheck: 'false', oninput: (e) => updateForm((st) => { st.uiLocales = e.target.value.trim(); }, { rerender: false }) })),
      field('max_age (seconds)', h('input.input.mono#f-maxage', { type: 'number', min: 0, value: f.maxAge, placeholder: 'e.g. 300', oninput: (e) => updateForm((st) => { st.maxAge = e.target.value; }, { rerender: false }) })),
      field('login_hint', h('input.input.mono#f-hint', { type: 'text', value: f.loginHint, placeholder: 'e-mail, username or phone number', autocomplete: 'off', oninput: (e) => updateForm((st) => { st.loginHint = e.target.value; }, { rerender: false }) })),
      h('div.field', {},
        h('span.field-label', 'PKCE'),
        h('label.check-row', { for: 'f-pkce' },
          h('input', { type: 'checkbox', id: 'f-pkce', checked: f.pkce, onchange: () => updateForm((st) => { st.pkce = !st.pkce; }) }),
          h('span', {}, 'S256 code challenge'),
        ),
      ),
      field('Extra parameters', h('textarea.input.mono.textarea#f-extra', {
        rows: 3, spellcheck: 'false', placeholder: 'one per line, e.g.\ndisplay=popup\nresponse_mode=form_post',
        oninput: (e) => updateForm((st) => { st.extraParams = e.target.value; }, { rerender: false }),
      }, f.extraParams || ''), { full: true, hint: 'Added to the URL as typed. A name that already exists (response_type, state, nonce, …) replaces that value.' }),
    ),
    { id: 'h-options', collapsible: true, summary });
}

/** Shown while a request started in this tab waits for its callback; lets the callback URL be pasted in. */
function pendingCard() {
  const pending = loadJson(sessionStorage, PENDING_KEY, null);
  if (!pending) return null;
  const target = pending.redirectUri || pageUrl;
  const elsewhere = target !== pageUrl;
  const finish = () => finishFromPastedUrl();
  return card('Finish the request',
    elsewhere
      ? ['The request started at ', formatIso(pending.startedAt), ' redirects to ', h('code', target), ', not to this page. After you authorize, copy the complete URL you land on (with ', h('code', 'code'), ' and ', h('code', 'state'), ') and paste it here.']
      : ['A request started at ', formatIso(pending.startedAt), ' is waiting for the provider to send you back here. If you came back by hand, paste the complete callback URL.'],
    [
      h('div.input-row', {},
        h('input.input.mono#f-callback', {
          type: 'url', placeholder: `${target}?code=…&state=…`, autocomplete: 'off', spellcheck: 'false', 'aria-label': 'Callback URL',
          onkeydown: (e) => { if (e.key === 'Enter') { e.preventDefault(); finish(); } },
        }),
        h('button.btn.btn-primary.btn-sm', { type: 'button', onclick: finish }, 'Finish'),
        h('button.btn.btn-ghost.btn-sm', { type: 'button', title: 'Forget this pending request', onclick: () => { saveJson(sessionStorage, PENDING_KEY, null); state.callbackPasteError = null; render(); } }, 'Discard'),
      ),
      state.callbackPasteError ? errorBanner(state.callbackPasteError) : null,
    ],
    { id: 'h-pending' });
}

function finishFromPastedUrl() {
  const raw = (document.getElementById('f-callback')?.value || '').trim();
  let url;
  try {
    url = new URL(raw);
  } catch {
    state.callbackPasteError = { error: 'invalid_url', error_description: 'Paste the complete URL from the address bar, starting with http:// or https://.' };
    return render();
  }
  if (!url.searchParams.has('code') && !url.searchParams.has('error')) {
    state.callbackPasteError = { error: 'not_a_callback', error_description: 'That URL carries neither a code nor an error parameter.' };
    return render();
  }
  state.callbackPasteError = null;
  handleCallback(url.href);
}

function exchangeCard(f) {
  const s = state.secrets;
  const on = exchanges(f);
  const modeSelect = h('select.input#f-mode', {
    onchange: (e) => {
      updateForm((st) => { st.mode = e.target.value; st.modeChosen = true; });
      if (f.issuer) loadDiscovery();
      if (exchanges()) loadKey();
    },
  },
    h('option', { value: 'request', selected: !on }, 'off — only build the request'),
    h('option', { value: 'direct', selected: f.mode === 'direct' }, 'in this browser (provider must allow CORS)'),
    h('option', { value: 'helper', selected: f.mode === 'helper' }, 'through a helper'),
  );
  if (!on) {
    return card('Code exchange', null,
      h('div.fields', {}, field('Exchange the code', modeSelect, { full: true, hint: 'Off: the page builds and opens the request, and whatever sits at the redirect URI handles the code.' })),
      { id: 'h-exchange', collapsible: true, summary: 'off · request only' });
  }

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

  const assertionField = needsKey
    ? field('Assertion audience', h('select.input#f-aud', {
        onchange: (e) => updateForm((st) => { st.assertionAudience = e.target.value; }),
      }, ASSERTION_AUDIENCES.map((a) => h('option', { value: a.id, selected: a.id === (f.assertionAudience || 'token_endpoint') }, a.label))),
      { hint: 'The aud of the signed assertion. Try the other value if the token endpoint answers unauthorized_client or invalid_client.' })
    : null;

  const keyUrlField = field(needsKey ? 'Private key URL' : 'Private key URL (optional)',
    h('div.input-row', {},
      h('input.input.mono#f-key-url', {
        type: 'url', value: f.keyUrl ?? '', placeholder: 'https://…/private-jwks.json — a JWK, a JWKS with your private keys, or PEM', autocomplete: 'off', spellcheck: 'false',
        oninput: (e) => updateForm((st) => { st.keyUrl = e.target.value.trim(); }, { rerender: false }),
        onkeydown: (e) => { if (e.key === 'Enter') { e.preventDefault(); fetchKeyFromUrl(); } },
      }),
      h('button.btn.btn-ghost.btn-sm', { type: 'button', disabled: state.keyLoading, onclick: () => fetchKeyFromUrl() }, state.keyLoading ? 'Loading…' : 'Load'),
    ),
    { full: true, hint: 'Fetched by this browser (the host must allow cross-origin requests), kept in this tab only, fetched again when you open the page. A JWKS may hold a sig key and an enc key.' });

  const keyField = field(needsKey ? 'Private key' : 'Private key (optional)',
    h('textarea.input.mono.textarea#f-key', {
      rows: 4, spellcheck: 'false', placeholder: needsKey ? 'JWK, JWKS or PEM — loaded from the URL above, or pasted' : 'JWK, JWKS or PEM — only to decrypt encrypted responses',
      oninput: (e) => { state.secrets.privateKey = e.target.value; state.secrets.keySource = null; saveSecrets(); },
      onchange: () => inspectKey(),
    }, s.privateKey),
    { full: true, hint: ['Signs the client assertion and decrypts JWE responses. The matching ', h('strong', 'public'), ' key must be in the JWKS at your registered jwks_uri.'] });

  let keyInfo = null;
  if (state.keyInfo?.key) {
    const k = state.keyInfo.key;
    const encKids = (k.decryption_kids || []).filter((id) => id !== k.kid);
    const found = k.keys_found;
    keyInfo = h('div.note.note-ok.field-full', {},
      h('div.row-between', {},
        h('span', {}, icon('check', 14, { strokeWidth: 3 }), ` Key loaded · ${k.kty} · ${k.alg} · kid `, h('code', k.kid),
          encKids.length ? [' · decrypts with kid ', encKids.map((id, i) => [i ? ', ' : null, h('code', id)])] : null),
        copyButton('Copy public JWK', () => pretty(k.public_jwk), 'btn-xs'),
      ),
      h('p.field-hint', {},
        s.keySource ? `Loaded from ${s.keySource.url} at ${formatIso(s.keySource.fetchedAt)}. ` : null,
        found && found.private > 1 ? `${found.private} private keys found${found.public ? ` (${found.public} public ignored)` : ''}. ` : null,
        'Your hosted JWKS must contain this public key with the same kid.'),
    );
  } else if (state.keyInfo?.error) {
    keyInfo = h('div.note.note-err.field-full', {}, icon('alert', 14), ` ${state.keyInfo.error.error_description}`);
  }

  return card('Code exchange', null,
    h('div.fields', {},
      field('Exchange the code', modeSelect, { full: true }),
      f.mode === 'helper'
        ? field('Helper URL', h('input.input.mono#f-helper', {
            type: 'url', value: f.helperUrl, placeholder: 'http://localhost:3000', spellcheck: 'false',
            oninput: (e) => updateForm((st) => { st.helperUrl = e.target.value.trim(); }, { rerender: false }),
            onchange: () => { if (f.issuer) loadDiscovery(); },
          }), { full: true, hint: 'A server that does discovery, the token exchange and UserInfo for providers without CORS (npm start in the repo).' })
        : null,
      field('Client authentication', authSelect),
      secretField,
      assertionField,
      keyUrlField,
      keyField,
      keyInfo,
    ),
    { id: 'h-exchange', collapsible: true, defaultOpen: true, summary: `${f.mode === 'helper' ? `helper · ${f.helperUrl}` : 'this browser'} · ${f.clientAuthMethod}` });
}

/** The authorization request as it will be sent, built from the form and this tab's draft state / nonce / PKCE. */
function authorizationRequest() {
  const f = state.form;
  const provider = discoveryFor(f.issuer);
  const d = state.draft;
  if (!provider || !d) return null;
  const body = buildStartRequest(f);
  const params = buildAuthorizationParams(body, { clientId: f.clientId.trim(), redirectUri: redirectUriFor(f), state: d.state, nonce: d.nonce, codeChallenge: body.pkce ? d.challenge : null });
  const url = new URL(provider.endpoints.authorization_endpoint);
  for (const [k, v] of params) url.searchParams.set(k, v);
  // What actually goes on the wire: an extra parameter may have replaced state, nonce or the challenge.
  const sent = Object.fromEntries(params);
  const values = { state: sent.state ?? null, nonce: sent.nonce ?? null, verifier: sent.code_challenge && sent.code_challenge === d.challenge ? d.verifier : null };
  return { body, params, url: url.href, provider, values };
}

/** The authorization URL split into endpoint and parameters; a parameter whose value changed since the last render flashes. */
function urlNodes(href) {
  const q = href.indexOf('?');
  const base = q === -1 ? href : href.slice(0, q);
  const pairs = q === -1 ? [] : href.slice(q + 1).split('&');
  const prev = state.urlParts;
  const next = {};
  const nodes = [h('span.url-base', base)];
  pairs.forEach((pair, i) => {
    const eq = pair.indexOf('=');
    const k = eq === -1 ? pair : pair.slice(0, eq);
    const v = eq === -1 ? '' : pair.slice(eq + 1);
    next[k] = v;
    const changed = prev !== null && prev[k] !== v;
    nodes.push(i === 0 ? '?' : '&', h('span.url-k', k), '=', h(`span.url-v${changed ? '.flash' : ''}`, v));
  });
  state.urlParts = next;
  return nodes;
}

function submitCard() {
  const f = state.form;
  const provider = discoveryFor(f.issuer);
  const problems = readinessProblems();
  const auth = authorizationRequest();

  let urlNode;
  if (auth) {
    urlNode = h('div.url-box', {},
      h('div.row-between', {},
        h('span.muted.small', `${auth.params.length} parameters · GET ${auth.provider.endpoints.authorization_endpoint}`),
        copyButton('Copy URL', auth.url, 'btn-xs'),
      ),
      h('pre.url-text', {}, urlNodes(auth.url)),
    );
  } else {
    urlNode = h('p.muted.small', provider ? 'Generating state, nonce and the PKCE challenge…' : 'Enter the issuer and load its discovery document to see the authorization URL.');
  }

  const problemList = problems.length ? h('ul.plain-list.muted.small', {}, problems.map((p) => h('li', p))) : null;
  const where = provider ? providerLabel().split('·')[0].trim() : null;

  if (!exchanges(f)) {
    // Request only: the values the other side needs are shown, and the request opens in a new tab so the form stays put.
    const ready = auth && !problems.length;
    const rows = auth ? [['state', auth.values.state], ['nonce', auth.values.nonce], ['code_verifier', auth.values.verifier]].filter(([, v]) => v) : [];
    const valuesNode = rows.length
      ? h('div.req-values', {},
          rows.map(([k, v]) => h('div.req-value', {},
            h('span.req-k', k),
            h('code.req-v', v),
            k === 'code_verifier' ? h('span.req-note', 'needed to redeem the code') : null,
            copyButton('Copy', v, 'btn-xs'),
          )),
          h('div', {}, h('button.btn.btn-ghost.btn-xs', { type: 'button', onclick: () => { state.openedAt = null; newDraft(); } }, icon('reset', 13, { strokeWidth: 2 }), ' New values')),
        )
      : null;
    const label = [where ? `Open at ${where}` : 'Open the request', icon('external', 17, { strokeWidth: 2 })];
    return card('Authorization request', null,
      [
        field('Authorization URL', urlNode, { full: true }),
        valuesNode ? field('Request values', valuesNode, { full: true, hint: 'Generated in this tab. They stay the same until you press New values or reload the page.' }) : null,
        h('div.cta', {},
          ready
            ? h('a.btn.btn-primary.btn-lg', { href: auth.url, target: '_blank', rel: 'noopener', onclick: () => noteOpened(auth) }, label)
            : h('button.btn.btn-primary.btn-lg', { type: 'button', disabled: true }, label),
          state.openedAt ? h('p.cta-note', {}, `Opened in a new tab at ${formatIso(state.openedAt)}.`) : null,
          problemList,
        ),
      ],
      { id: 'h-submit' });
  }

  return card('Authorize', 'The exact URL the button opens. state, nonce and PKCE stay in this tab.',
    [
      field('Authorization URL', urlNode, { full: true }),
      h('div.cta', {},
        h('button.btn.btn-primary.btn-lg', { type: 'button', disabled: !auth || problems.length > 0 || state.starting, onclick: startAuthorization },
          state.starting ? 'Redirecting…' : where ? `Authorize with ${where}` : 'Authorize', icon('arrow', 18)),
        problemList,
        state.startError ? errorBanner(state.startError) : null,
      ),
    ],
    { id: 'h-submit' });
}

/** Remembers which request was opened in a new tab, so a callback that lands on this page can be matched by its state. */
function noteOpened(auth) {
  state.openedAt = new Date().toISOString();
  saveJson(localStorage, SENT_KEY, { startedAt: state.openedAt, state: auth.values.state });
  setTimeout(renderPreviewOnly, 0); // after the browser has followed the link
}

function readinessProblems() {
  const f = state.form;
  const problems = [];
  if (!f.issuer.trim()) problems.push('Enter the issuer.');
  else if (!discoveryFor(f.issuer)) problems.push('Load the discovery document first.');
  if (!f.clientId.trim()) problems.push('Enter the client ID.');
  try {
    if (!['http:', 'https:'].includes(new URL(redirectUriFor(f)).protocol)) throw new Error();
  } catch {
    problems.push('The redirect URI must be an absolute http(s) URL.');
  }
  if (exchanges(f)) {
    if (f.clientAuthMethod.startsWith('client_secret') && !state.secrets.clientSecret) problems.push('Enter the client secret (Code exchange).');
    if (f.clientAuthMethod === 'private_key_jwt' && !state.secrets.privateKey.trim()) problems.push('Load or paste the private key (Code exchange).');
    if (f.mode === 'helper' && !/^https?:\/\//.test(f.helperUrl)) problems.push('Enter the helper URL (Code exchange).');
  }
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

/** Generates the state, nonce and PKCE pair for the request being built; the submit card shows the resulting URL. */
async function newDraft() {
  let pkce = null;
  try {
    pkce = await pkcePair();
  } catch {
    /* no WebCrypto (insecure context): readinessProblems() explains, the URL is shown without PKCE */
  }
  state.draft = { state: randomUrlSafe(24), nonce: randomUrlSafe(24), verifier: pkce?.verifier || null, challenge: pkce?.challenge || null };
  renderPreviewOnly();
}

async function startAuthorization() {
  const f = state.form;
  const auth = authorizationRequest();
  if (!auth || readinessProblems().length) return;
  state.starting = true;
  state.startError = null;
  renderPreviewOnly();
  try {
    const { body, params, url, provider, values } = auth;
    const redirect = redirectUriFor(f);

    saveJson(sessionStorage, PENDING_KEY, {
      startedAt: new Date().toISOString(),
      issuer: f.issuer.trim(),
      clientId: f.clientId.trim(),
      clientAuthMethod: f.clientAuthMethod,
      assertionAudience: f.assertionAudience || 'token_endpoint',
      mode: f.mode,
      helperUrl: f.helperUrl,
      redirectUri: redirect,
      state: values.state,
      nonce: values.nonce,
      codeVerifier: values.verifier,
      maxAge: body.max_age ?? null,
      request: {
        url,
        endpoint: provider.endpoints.authorization_endpoint,
        params: params.map(([k, v]) => ({ k, v })),
        scopes: body.scopes,
        claims: body.claims,
        redirectUri: redirect,
      },
      endpoints: provider.endpoints,
    });
    state.result = null;
    saveResult();
    window.location.assign(url);
  } catch (err) {
    state.starting = false;
    state.startError = { error: 'start_failed', error_description: err.message };
    renderPreviewOnly();
  }
}

// --- back from the provider: finish the flow -------------------------------------------------

async function handleCallback(callbackUrl = location.href) {
  const cb = new URL(callbackUrl);
  const query = Object.fromEntries(cb.searchParams);
  const pending = loadJson(sessionStorage, PENDING_KEY, null);
  saveJson(sessionStorage, PENDING_KEY, null);
  const callback = { url: cb.origin === location.origin ? `${cb.pathname}${cb.search}` : cb.href, query, receivedAt: new Date().toISOString() };
  if (callbackUrl === location.href) history.replaceState({}, '', location.pathname); // the one-time code must not stay in the address bar

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
    // Nothing to redeem with: the request was only built here (or opened from another tab). Show what came back.
    const sent = loadJson(localStorage, SENT_KEY, null);
    const stateCheck = !sent?.state || !query.state ? 'unknown' : sent.state === query.state ? 'match' : 'mismatch';
    return finish({ status: 'callback', callback, stateCheck, sentAt: sent?.startedAt || null });
  }
  if (query.state && query.state !== pending.state) {
    return finish({ status: 'error', callback, request: pending.request, config: configSummary(pending), error: { stage: 'callback', error: 'state_mismatch', error_description: `The state in the callback (${query.state}) is not the one this tab sent (${pending.state}).` } });
  }
  if (query.error) {
    return finish({ status: 'error', callback, request: pending.request, config: configSummary(pending), error: { stage: 'authorization', error: query.error, error_description: query.error_description || 'The provider returned an error instead of a code.' } });
  }

  if (!state.secrets.privateKey.trim() && state.form.keyUrl) await fetchKeyFromUrl({ silent: true });
  const secrets = state.secrets;
  const clientAuth = { method: pending.clientAuthMethod };
  if (pending.clientAuthMethod.startsWith('client_secret')) clientAuth.client_secret = secrets.clientSecret;
  if (pending.clientAuthMethod === 'private_key_jwt') clientAuth.assertion_audience = pending.assertionAudience || 'token_endpoint';
  if (secrets.privateKey.trim()) clientAuth.private_key = secrets.privateKey;

  const res = await backendFor({ mode: pending.mode, helperUrl: pending.helperUrl }).token({
    issuer: pending.issuer,
    client_id: pending.clientId,
    client_auth: clientAuth,
    callback_url: callbackUrl,
    redirect_uri: pending.redirectUri || pageUrl,
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
        h('a.btn.btn-primary', { href: pageUrl, onclick: (e) => { e.preventDefault(); show('build'); } }, 'Build a request', icon('arrow', 18)),
      ),
    );
  }
  if (r.status === 'callback') return callbackView(r);
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
      h('p.page-lead', `${r.config.issuer} · client ${r.config.clientId} · ${r.config.clientAuthMethod} · exchanged ${r.config.mode === 'helper' ? 'through the helper' : 'in this browser'}. Below is everything the ID token says — about the user and about itself.`),
    ),
    h('div.columns', {},
      h('section.col-main', {}, idTokenCard(r), userinfoCard(r)),
      h('aside.col-side', {}, tokenResponseCard(r), checksCard('ID token checks', 'OpenID Connect Core §3.1.3.7', r.idToken.checks, 'h-checks'), requestSentCard(r)),
    ),
    h('div.actions', {},
      h('a.btn.btn-primary.btn-lg', { href: pageUrl, onclick: (e) => { e.preventDefault(); show('build'); } }, icon('reset', 16, { strokeWidth: 2 }), 'Start a new request'),
      copyButton('Copy result as JSON', () => pretty(r)),
    ),
  );
}

/** A callback that this page does not redeem: the request was only built here, or no request was waiting in this tab. */
function callbackView(r) {
  const q = r.callback.query || {};
  const stateNote = r.stateCheck === 'match'
    ? ['state matches the request opened at ', formatIso(r.sentAt)]
    : r.stateCheck === 'mismatch'
      ? 'state differs from the last request opened in this browser'
      : 'state not checked, no opened request to compare with';
  const banner = q.error
    ? errorBanner({ stage: 'authorization', error: q.error, error_description: q.error_description || 'The provider returned an error instead of a code.' })
    : h(`div.banner.${r.stateCheck === 'mismatch' ? 'banner-err' : 'banner-ok'}`, { role: 'status' },
        icon(r.stateCheck === 'mismatch' ? 'alert' : 'circleCheck', 20),
        h('div', {}, h('div', {}, h('strong', 'Callback received'), ' — ', stateNote, '.'), h('code.mono.small.break', r.callback.url)),
      );
  return h('main.main', {},
    banner,
    h('div.page-head', {},
      h('h1.page-title', q.error ? 'The provider returned an error' : 'Authorization code received'),
      h('p.page-lead', exchanges() ? 'No request was waiting in this tab, so the code was not redeemed.' : 'Code exchange is off, so the code was not redeemed.'),
    ),
    card('Callback parameters', null,
      [
        kvRows(Object.entries(q).map(([k, v]) => ({ k, v }))),
        q.code ? h('div', {}, copyButton('Copy code', q.code, 'btn-sm')) : null,
      ],
      { id: 'h-cbq' }),
    h('div.actions', {},
      h('a.btn.btn-primary.btn-lg', { href: pageUrl, onclick: (ev) => { ev.preventDefault(); show('build'); } }, icon('reset', 16, { strokeWidth: 2 }), 'Back to the request builder'),
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
      h('a.btn.btn-primary.btn-lg', { href: pageUrl, onclick: (ev) => { ev.preventDefault(); show('build'); } }, icon('reset', 16, { strokeWidth: 2 }), 'Back to the request builder'),
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
window.__oidcPlayground = { state, pageUrl };
