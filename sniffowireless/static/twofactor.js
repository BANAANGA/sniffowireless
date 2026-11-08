'use strict';
/* Settings → Account → Two-factor authentication: sign in with a code from an authenticator app as well as the password. */

function loadQr() {
  if (window.qrcode) return Promise.resolve(window.qrcode);
  return new Promise(res => {
    const s = document.createElement('script');
    s.src = '/vendor/qrcode.js';
    s.onload = () => res(window.qrcode || null);
    s.onerror = () => res(null);
    document.head.appendChild(s);
  });
}

async function twoFactorPanel(el) {
  let st;
  try { st = await api('/api/me/2fa'); } catch { el.hidden = true; return; }   // e.g. an account that is not stored here (AUTH_DISABLED)

  function render() {
    el.innerHTML = `<header><h2>Two-factor authentication</h2>${st.enabled ? '<span class="tag on">on</span>' : '<span class="tag">off</span>'}</header><div class="body">
      <p style="margin-top:0" class="muted">${st.enabled ? `Signing in asks for a code from your authenticator app after the password. ${st.recovery_left} recovery code${st.recovery_left === 1 ? '' : 's'} left.`
        : 'Add a code from an authenticator app (any TOTP app: Aegis, Google Authenticator, 1Password, …) to your password. API tokens and sensors are not affected.'}</p>
      <button class="btn ${st.enabled ? '' : 'primary'}" id="tfa-btn">${st.enabled ? 'Turn off…' : 'Set up…'}</button></div>`;
    el.querySelector('#tfa-btn').onclick = st.enabled ? turnOff : setUp;
  }

  function setUp() {
    openModal('Turn on two-factor login', `<p style="margin-top:0">Confirm your password to start.</p>
      <label class="field">Password<input type="password" name="password" autocomplete="current-password" required></label>`,
    async f => {
      const r = await send('POST', '/api/me/2fa/begin', { password: f.elements.password.value });
      setTimeout(() => scan(r), 50);
    }, { submit: 'Continue' });
  }

  async function scan(r) {
    const qr = await loadQr();
    let svg = '';
    if (qr) { const q = qr(0, 'M'); q.addData(r.uri); q.make(); svg = q.createSvgTag({ cellSize: 4, margin: 2, scalable: true }); }
    openModal('Scan this with your authenticator app',
      `${svg ? `<div style="background:#fff;padding:6px;width:200px;margin:0 auto 10px;border-radius:6px">${svg}</div>` : ''}
       <p class="small-text" style="margin-top:0">${svg ? 'Or enter this key by hand' : 'Enter this key in your authenticator app'}: <code style="user-select:all;word-break:break-all">${esc(r.secret)}</code> (time based, 6 digits).</p>
       <label class="field">The 6 digit code the app shows now<input name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="8" required></label>`,
    async f => {
      const done = await send('POST', '/api/me/2fa/enable', { code: f.elements.code.value });
      st = await api('/api/me/2fa');
      render();
      setTimeout(() => recovery(done.recovery_codes), 50);
    }, { submit: 'Turn on' });
  }

  function recovery(codes) {
    openModal('Keep these recovery codes', `<p style="margin-top:0">Each works once, if you lose your phone. <b>They are shown only now.</b> Other sessions of yours were signed out.</p>
      <pre class="mono" id="rc" style="user-select:all;margin:0">${esc(codes.join('\n'))}</pre>`, async () => {}, { submit: 'I saved them' });
  }

  function turnOff() {
    openModal('Turn off two-factor login', `<label class="field">Password<input type="password" name="password" autocomplete="current-password" required></label>
      <label class="field">A code from the app (or a recovery code)<input name="code" autocomplete="one-time-code" maxlength="32" required></label>`,
    async f => {
      await send('POST', '/api/me/2fa/disable', { password: f.elements.password.value, code: f.elements.code.value });
      st = await api('/api/me/2fa');
      toast('Two-factor login is off');
      render();
    }, { submit: 'Turn off', danger: true });
  }
  render();
}
