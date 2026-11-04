'use strict';
// Click-to-sort for every table in the app. Tables that sort on the server (headers with data-sort, e.g. the device
// list) keep their own behaviour. The chosen sort is remembered per page and table and re-applied when the table is
// re-rendered by a refresh. A cell can give its sort value explicitly with data-v; otherwise it is read from the text
// ("5m ago", "1h 20m", "-67 dBm", "1.2 MB", "1,234", plain text).

(() => {
  const GROUP = (1000).toLocaleString().replace(/\d/g, '') || ',';
  const DECIMAL = (1.5).toLocaleString().replace(/\d/g, '') || '.';
  const UNITS = { s: 1, m: 60, h: 3600, d: 86400 };
  const SIZES = { kb: 1e3, mb: 1e6, gb: 1e9, b: 1 };
  const state = new Map();  // page|headers -> { col, dir }

  function parse(cell) {
    if (!cell) return null;
    if (cell.dataset.v !== undefined) {
      const v = cell.dataset.v, n = Number(v);
      return v === '' ? null : Number.isFinite(n) ? n : v.toLowerCase();
    }
    const t = cell.textContent.replace(/\s+/g, ' ').trim();
    if (!t || t === '—' || t === '-' || t === '?') return null;
    if (t === 'never') return -Infinity;
    let m = t.match(/^(\d+)([smhd]) ago$/);
    if (m) return -m[1] * UNITS[m[2]];  // larger = more recent
    if (/^(\d+[dhms] ?)+$/.test(t)) return t.split(' ').reduce((a, p) => a + parseInt(p, 10) * UNITS[p.slice(-1)], 0);
    m = t.match(/^(-?\d+) dBm\b/);
    if (m) return +m[1];
    const plain = t.split(GROUP).join('').replace(DECIMAL, '.');
    m = plain.match(/^(-?\d+(?:\.\d+)?) ?(%|kB|MB|GB|B)?$/i);
    if (m) return +m[1] * (m[2] && m[2] !== '%' ? SIZES[m[2].toLowerCase()] : 1);
    m = plain.match(/^(-?\d+(?:\.\d+)?)\b/);  // "12 rand", "36 · 5G"
    if (m && /^[\d.\- ]/.test(t)) return { n: +m[1], s: t.toLowerCase() };
    return t.toLowerCase();
  }
  const key = v => (v && typeof v === 'object') ? v.n : v;
  function cmp(a, b) {
    a = key(a); b = key(b);
    if (a === null) return b === null ? 0 : 1;
    if (b === null) return -1;
    if (typeof a === 'number' && typeof b === 'number') return a - b;
    return String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: 'base' });
  }

  const headRow = table => table.tHead && table.tHead.rows[table.tHead.rows.length - 1];
  function sortable(table) {
    const hr = headRow(table);
    if (!hr || table.dataset.nosort !== undefined || table.querySelector('th[data-sort]')) return false;
    if ([...hr.cells].some(c => c.colSpan > 1)) return false;
    const body = table.tBodies[0];
    return !!body && ![...body.rows].some(r => [...r.cells].some(c => c.colSpan > 1));
  }
  const sig = table => location.hash.split('?')[0] + '|' + [...headRow(table).cells].map(c => c.textContent.trim()).join('|');

  function apply(table, col, dir) {
    const body = table.tBodies[0];
    const rows = [...body.rows].map((r, i) => ({ r, i, v: parse(r.cells[col]) }));
    rows.sort((a, b) => {
      if (a.v === null || b.v === null) return cmp(a.v, b.v) || a.i - b.i;  // empty cells last either way
      return (dir === 'asc' ? cmp(a.v, b.v) : cmp(b.v, a.v)) || a.i - b.i;
    });
    rows.forEach(x => body.appendChild(x.r));
    [...headRow(table).cells].forEach((c, i) => {
      if (i === col) c.setAttribute('aria-sort', dir === 'asc' ? 'ascending' : 'descending'); else c.removeAttribute('aria-sort');
    });
  }

  function prepare(table) {
    if (!sortable(table)) return;
    const hr = headRow(table);
    [...hr.cells].forEach(c => { if (c.textContent.trim() && !c.classList.contains('nosort')) c.classList.add('csort'); });
    const st = state.get(sig(table));
    if (st) apply(table, st.col, st.dir);
  }

  let observer = null, pending = false;
  function scan() {
    pending = false;
    observer.disconnect();
    document.querySelectorAll('table').forEach(prepare);
    observer.takeRecords();
    observer.observe(document.body, { childList: true, subtree: true });
  }

  document.addEventListener('click', e => {
    const th = e.target.closest('th.csort');
    if (!th || e.target.closest('input, button, a, select, label')) return;
    const table = th.closest('table');
    if (!table || !sortable(table)) return;
    const col = th.cellIndex, k = sig(table), cur = state.get(k);
    // First click: numbers/times largest (most recent) first, text A→Z; next click flips.
    const sample = [...table.tBodies[0].rows].map(r => parse(r.cells[col])).find(v => v !== null);
    const first = typeof key(sample) === 'number' ? 'desc' : 'asc';
    const dir = cur && cur.col === col ? (cur.dir === 'asc' ? 'desc' : 'asc') : first;
    state.set(k, { col, dir });
    observer.disconnect();
    apply(table, col, dir);
    observer.takeRecords();
    observer.observe(document.body, { childList: true, subtree: true });
  });

  const start = () => {
    observer = new MutationObserver(() => { if (!pending) { pending = true; setTimeout(scan, 30); } });
    scan();
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start, { once: true }); else start();
})();
