'use strict';
/* Reset a capture adapter that stopped working (buttons in the overview's Sensors panel, admins only). */

function resetAdapter(sensor, name) {
  const kind = name.split(':')[0], iface = name.split(':').slice(1).join(':');
  const what = { wifi: 'The interface is brought down and up again; monitor mode is set again by itself.', bt: 'The Bluetooth device is taken down, reset and brought up.',
    zigbee: 'The serial link is closed and the stick is opened again.', lora: 'The serial link is closed and the board is opened again.' }[kind] || '';
  openModal(`Reset ${esc(iface)}${sensor === 'local' ? '' : ` on ${esc(sensor)}`}`,
    `<p style="margin-top:0">${what} Capture on this adapter stops for a few seconds.${sensor === 'local' ? '' : ' A remote sensor does it with its next upload, and needs a recent version of sniffowireless to understand the request.'}</p>
     <label class="check"><input type="checkbox" name="usb"> Also reset the USB device, like unplugging and plugging it back in <span class="faint">(for an adapter that does not respond at all; needs a privileged container)</span></label>`,
    async f => {
      const r = await send('POST', '/api/adapters/reset', { sensor, name, usb: fv(f, 'usb') });
      toast(r.done ? 'Reset: ' + r.steps.join(', ') : 'Requested: the sensor does it with its next upload');
    }, { submit: 'Reset' });
}
