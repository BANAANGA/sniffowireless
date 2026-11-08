'use strict';
/* Settings → LoRa flasher: writes the bundled lora-sniffer firmware to a Heltec WiFi LoRa 32 V3 plugged into the computer
   you are browsing from, over Web Serial with esptool-js. The server only hands out the firmware image. */

SETTINGS_VIEWS.loraflasher = async function (el) {
  const supported = !!navigator.serial, secure = window.isSecureContext;
  let fw = null;
  try { fw = await api('/api/lora/firmware'); } catch (e) { /* this build has no firmware image */ }
  const kb = n => Math.round(n / 1024) + ' kB';
  const cmd = fw ? `esptool.py --chip esp32s3 --port /dev/ttyUSB0 write_flash 0x0 ${fw.file}` : '';

  el.innerHTML = `<p class="muted" style="margin-top:0">Put the receive-only LoRa firmware on a <b>Heltec WiFi LoRa 32 V3</b>. The board must be plugged into <b>this computer</b> (the one running your browser), not necessarily the server. Afterwards plug it into the machine that runs sniffowireless and set <code>LORA_DEVICES</code> (see README → LoRa).</p>
    ${!fw ? '<div class="callout"><span class="err">This build contains no firmware image.</span> Build one with <code>python3 scripts/build_firmware.py</code>.</div>' : `
    <section class="panel" style="max-width:760px"><header><h2>${esc(fw.title)}</h2><span class="faint">version ${esc(fw.version)} · built ${esc(fw.built)} · ${kb(fw.size)} · sha256 ${esc(fw.sha256.slice(0, 12))}</span></header><div class="body">
      <p style="margin-top:0"><b>Flashing replaces whatever is on the board</b> (for example Meshtastic). Tick the box below to save a copy first so you can restore it later.</p>
      ${!supported || !secure ? `<div class="callout"><span class="warn-text">${!supported ? 'This browser cannot talk to serial ports (Web Serial). Use Chrome, Edge or another Chromium based browser.' :
        'Web Serial only works on a secure page. Open sniffowireless over <b>https://</b>, or on <b>http://localhost</b> (for example through <code>ssh -L 8080:localhost:8080 your-server</code>).'}</span>
        <div class="small-text" style="margin-top:8px">Or flash from a terminal: <a href="${esc(fw.url)}" download>download the image</a> and run</div><pre class="mono small-text" style="margin:6px 0 0;white-space:pre-wrap">${esc(cmd)}</pre></div>` : ''}
      <label class="row" style="gap:8px;margin:12px 0"><input type="checkbox" id="fl-backup" checked> Save a copy of the current firmware first <span class="faint">(8 MB, about 2 minutes)</span></label>
      <div class="row"><button class="btn primary" id="fl-go" ${supported && secure ? '' : 'disabled'}>Select board and flash</button><span class="faint small-text" id="fl-state"></span></div>
      <div id="fl-bar" style="height:6px;background:var(--border,#333);border-radius:3px;margin:12px 0;overflow:hidden" hidden><i id="fl-fill" style="display:block;height:100%;width:0;background:#3ecf8e"></i></div>
      <pre id="fl-log" class="mono small-text" style="max-height:240px;overflow:auto;margin:8px 0 0;white-space:pre-wrap" hidden></pre>
      <p class="faint small-text" style="margin-bottom:0">If the board is not found or does not respond: hold <b>PRG</b>, tap <b>RST</b>, release <b>PRG</b>, then try again. If this computer is the sniffowireless server and its LoRa sensor already uses the board, stop that sensor first: only one program can use the port.</p>
    </div></section>`}`;
  if (!fw || !supported || !secure) return;

  const $ = id => el.querySelector('#' + id), logEl = $('fl-log'), state = $('fl-state'), go = $('fl-go');
  const log = t => { logEl.hidden = false; logEl.textContent += t + '\n'; logEl.scrollTop = logEl.scrollHeight; };
  const progress = f => { $('fl-bar').hidden = false; $('fl-fill').style.width = Math.round(Math.max(0, Math.min(1, f)) * 100) + '%'; };
  const bin2str = u8 => { let s = ''; for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000)); return s; };
  const sleep = ms => new Promise(r => setTimeout(r, ms));

  go.onclick = async () => {
    go.disabled = true; logEl.textContent = ''; progress(0);
    let port, transport;
    try {
      const { ESPLoader, Transport } = await import('/vendor/esptool.bundle.js');
      state.textContent = 'Choose the board in the browser dialog…';
      port = await navigator.serial.requestPort({ filters: [{ usbVendorId: 0x10C4 }, { usbVendorId: 0x303A }, { usbVendorId: 0x1A86 }] });
      transport = new Transport(port, false);
      const loader = new ESPLoader({ transport, baudrate: 921600, romBaudrate: 115200,
        terminal: { clean() { logEl.textContent = ''; }, writeLine: log, write: t => log(t) } });
      state.textContent = 'Connecting…';
      const chip = await loader.main();
      log('Chip: ' + chip);
      if (!/ESP32-S3/i.test(chip)) throw new Error(`This is not an ESP32-S3 (${chip}); the Heltec V3 has one. Nothing was written.`);

      if ($('fl-backup').checked) {
        state.textContent = 'Saving a copy of the current firmware…';
        const data = await loader.readFlash(0, 0x800000, (_, done, total) => progress(done / total));
        const a = document.createElement('a');
        a.href = URL.createObjectURL(new Blob([data], { type: 'application/octet-stream' }));
        a.download = `heltec-v3-original-${new Date().toISOString().slice(0, 10)}.bin`;
        a.click();
        log(`Saved ${a.download} (${data.length} bytes). Keep it: restoring it later is a flash of this file at address 0.`);
      }

      state.textContent = 'Downloading the firmware…';
      const buf = new Uint8Array(await (await fetch(fw.url, { credentials: 'same-origin' })).arrayBuffer());
      if (buf.length !== fw.size) throw new Error('The firmware download is incomplete.');
      const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', buf))).map(b => b.toString(16).padStart(2, '0')).join('');
      if (digest !== fw.sha256) throw new Error('The firmware download does not match its checksum. Nothing was written.');

      state.textContent = 'Writing the firmware…'; progress(0);
      await loader.writeFlash({ fileArray: [{ data: bin2str(buf), address: fw.address }], flashSize: 'keep', flashMode: 'keep', flashFreq: 'keep',
        eraseAll: false, compress: true, reportProgress: (_, written, total) => progress(written / total) });
      progress(1);
      log('Written and verified by the chip.');
      await loader.after('hard_reset');
      await transport.disconnect();
      transport = null;

      state.textContent = 'Checking that the board answers…';
      await port.open({ baudRate: 115200 });
      const w = port.writable.getWriter(), rd = port.readable.getReader(), dec = new TextDecoder();
      let text = '', ok = false;
      const until = Date.now() + 8000;
      await sleep(1500);
      while (Date.now() < until && !ok) {
        await w.write(new TextEncoder().encode('PING\n'));
        const t = await Promise.race([rd.read(), sleep(700).then(() => null)]);
        if (t && t.value) text += dec.decode(t.value);
        ok = /PONG/.test(text);
      }
      try { w.releaseLock(); await rd.cancel(); rd.releaseLock(); await port.close(); } catch (e) { /* closing is best effort */ }
      if (!ok) throw new Error('The firmware was written but the board did not answer. Unplug it, plug it in again and check the server page LoRa.');
      state.textContent = 'Done.';
      log('The board answers as lora-sniffer. Plug it into the sniffowireless machine and set LORA_DEVICES.');
      toast('Firmware flashed');
    } catch (e) {
      if (e && e.name === 'NotFoundError') state.textContent = 'No board selected.';
      else { state.textContent = 'Failed.'; log('Error: ' + (e && e.message || e)); toast(String(e && e.message || e), true); }
      try { if (transport) await transport.disconnect(); } catch (_) { /* already closed */ }
    } finally { go.disabled = false; }
  };
};
