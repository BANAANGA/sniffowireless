'use strict';
/* Reset a capture adapter that stopped working (buttons in the overview's Sensors panel, admins only). */

function resetAdapter(sensor, name) {
  const kind = name.split(':')[0], iface = name.split(':').slice(1).join(':');
  const what = { wifi: 'The interface is brought down and up again; monitor mode is set again by itself.', bt: 'The Bluetooth device is taken down, reset and brought up.',
    zigbee: 'The serial link is closed and the stick is opened again.', lora: 'The serial link is closed and the board is opened again.' }[kind] || '';
  openModal(`Reset ${iface}${sensor === 'local' ? '' : ` on ${sensor}`}`,
    `<p style="margin-top:0">${what} Capture on this adapter stops for a few seconds.${sensor === 'local' ? '' : ' A remote sensor does it with its next upload, and needs a recent version of sniffowireless to understand the request.'}</p>
     <label class="check"><input type="checkbox" name="usb"> Also reset the USB device, like unplugging and plugging it back in <span class="faint">(for an adapter that does not respond at all; needs a privileged container)</span></label>`,
    async f => {
      const r = await send('POST', '/api/adapters/reset', { sensor, name, usb: fv(f, 'usb') });
      toast(r.done ? 'Reset: ' + r.steps.join(', ') : 'Requested: the sensor does it with its next upload');
    }, { submit: 'Reset' });
}

/* Update the firmware of a LoRa board that sits on this server or on a remote sensor (no browser connection to the board needed). */
async function flashLora(sensor, name) {
  const iface = name.split(':').slice(1).join(':');
  let m = null;
  try { m = await api('/api/lora/firmware'); } catch (e) { toast(e.message || 'This build has no firmware image'); return; }
  const remote = sensor !== 'local';
  openModal(`Update the firmware of ${iface}${remote ? ` on ${sensor}` : ''}`,
    `<p style="margin-top:0">Writes sniffer firmware version <b>${esc(String(m.version))}</b> (${esc(m.title || m.name)}) to the board.
      ${remote ? 'The sensor downloads the image from this server with its next upload, then flashes the board over its own USB port.' : 'This server flashes the board over its USB port.'}
      It takes about a minute, and LoRa capture on this board stops until the board has restarted.</p>
     <p class="faint">The board is put into its bootloader with the USB-serial reset lines, so it must be a Heltec WiFi LoRa 32 V3 (or the same wiring).
      A failed update leaves the board in its bootloader: try again, or use the web flasher (Settings &rarr; LoRa flasher).${remote ? ' A sensor needs a version of sniffowireless that knows this request; older ones ignore it.' : ''}</p>`,
    async () => {
      const r = await send('POST', '/api/lora/flash', { sensor, name });
      toast(r.queued ? 'Requested: the sensor starts the update with its next upload' : 'Update started: see the board\'s status note');
    }, { submit: 'Update firmware' });
}
