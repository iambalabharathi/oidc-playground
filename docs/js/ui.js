// Tiny DOM helpers — no framework, no build step.

/** h('div.card#id', { onclick, aria: {...}, data: {...} }, ...children) */
export function h(spec, attrs = {}, ...children) {
  const tagMatch = spec.match(/^[a-z][a-z0-9-]*/i);
  const el = document.createElement(tagMatch ? tagMatch[0] : 'div');
  for (const token of spec.slice(tagMatch ? tagMatch[0].length : 0).match(/[#.][\w-]+/g) || []) {
    if (token[0] === '#') el.id = token.slice(1);
    else el.classList.add(token.slice(1));
  }
  if (attrs && typeof attrs === 'object' && !(attrs instanceof Node) && !Array.isArray(attrs)) {
    for (const [key, value] of Object.entries(attrs)) {
      if (value === undefined || value === null || value === false) continue;
      if (key === 'class') el.className += (el.className ? ' ' : '') + value;
      else if (key === 'style' && typeof value === 'object') Object.assign(el.style, value);
      else if (key === 'dataset') Object.assign(el.dataset, value);
      else if (key.startsWith('on') && typeof value === 'function') el.addEventListener(key.slice(2).toLowerCase(), value);
      else if (key === 'html') el.innerHTML = value;
      else if (value === true) el.setAttribute(key, '');
      else el.setAttribute(key, String(value));
    }
  } else {
    children.unshift(attrs);
  }
  append(el, children);
  return el;
}

export function append(el, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

export function clear(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
  return el;
}

const ICON_PATHS = {
  check: '<polyline points="20 6 9 17 4 12"/>',
  lock: '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
  arrow: '<line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/>',
  chevron: '<polyline points="9 18 15 12 9 6"/>',
  copy: '<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
  reset: '<polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/>',
  dash: '<line x1="6" y1="12" x2="18" y2="12"/>',
  alert: '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>',
  circleCheck: '<circle cx="12" cy="12" r="10"/><polyline points="16 9 10.5 15 8 12.5"/>',
  external: '<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>',
};

export function icon(name, size = 16, extra = {}) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('width', size);
  svg.setAttribute('height', size);
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', extra.strokeWidth || 2.5);
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  if (extra.label) {
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', extra.label);
  } else {
    svg.setAttribute('aria-hidden', 'true');
  }
  svg.innerHTML = ICON_PATHS[name] || '';
  return svg;
}

export function formatTime(seconds) {
  if (typeof seconds !== 'number') return '';
  return new Intl.DateTimeFormat(undefined, {
    day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit', timeZoneName: 'short',
  }).format(new Date(seconds * 1000));
}

export function formatIso(iso) {
  if (!iso) return '';
  return new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(new Date(iso));
}

export function pretty(value) {
  return JSON.stringify(value, null, 2);
}

export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

/** A button that briefly confirms the copy. */
export function copyButton(label, getText, extraClass = '') {
  const btn = h('button.btn.btn-ghost' + (extraClass ? '.' + extraClass.replace(/\s+/g, '.') : ''), { type: 'button' }, icon('copy', 15, { strokeWidth: 2 }), ' ', h('span', label));
  btn.addEventListener('click', async () => {
    const ok = await copyText(typeof getText === 'function' ? getText() : getText);
    const span = btn.querySelector('span');
    span.textContent = ok ? 'Copied' : 'Copy failed';
    setTimeout(() => (span.textContent = label), 1500);
  });
  return btn;
}

export function truncateMiddle(text, max = 48) {
  const s = String(text ?? '');
  if (s.length <= max) return s;
  return `${s.slice(0, Math.ceil(max / 2) - 1)}…${s.slice(-Math.floor(max / 2) + 1)}`;
}
