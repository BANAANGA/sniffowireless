'use strict';
let setup = false;
const f = document.getElementById('form');
const $ = id => document.getElementById(id);
fetch('/api/auth/state').then(r => r.json()).then(st => {
  if (st.user) { location.href = '/'; return; }
  setup = st.setup;
  if (setup) {
    $('title').textContent = 'Create the admin account';
    $('intro').textContent = 'No accounts exist yet. The first account is an administrator; you can add more users later.';
    $('code-field').hidden = $('pw2-field').hidden = false;
    f.password.autocomplete = 'new-password';
    f.password.minLength = 10;
    $('submit').textContent = 'Create account';
    f.code.focus();
  }
});
f.onsubmit = async e => {
  e.preventDefault();
  $('err').textContent = '';
  if (setup && f.password.value !== f.password2.value) { $('err').textContent = 'Passwords do not match'; return; }
  const body = { username: f.username.value.trim(), password: f.password.value };
  if (setup) body.code = f.code.value.trim();
  $('submit').disabled = true;
  const r = await fetch(setup ? '/api/auth/setup' : '/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  $('submit').disabled = false;
  if (r.ok) { location.href = '/'; return; }
  const d = (await r.json().catch(() => ({}))).detail;
  $('err').textContent = Array.isArray(d) ? d.map(x => x.msg).join('; ') : d || 'Sign-in failed';
};
