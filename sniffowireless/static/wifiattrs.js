'use strict';
/* Device-page rows for the extra Wi-Fi attributes (see wifiattrs.py): what an access point says about itself in its
   beacons, what a client says it can do, its link rate and, when switched on, other addresses it may have used. */

const AKM_HELP = {
  'PSK': 'WPA2-Personal: one shared password.', 'SAE': 'WPA3-Personal: password with SAE, which resists offline guessing.',
  'OWE': 'Opportunistic Wireless Encryption: encrypted without a password (open networks with encryption).',
  '802.1X': 'Enterprise login (each user signs in, usually through a RADIUS server).', 'DPP': 'Device Provisioning Protocol.',
  'CCKM': 'Cisco fast roaming.',
};
const ROAM_HELP = { '11k': 'Neighbour reports: tells clients which other access points to try.', '11v': 'BSS transition: can steer clients to another access point.', '11r': 'Fast BSS transition: quick, secure roaming between access points.' };

function wifiAkmTag(a) {
  const base = a.replace(/^FT-/, '').replace(/-SHA\d+$/, '').replace(/-EXT$/, '');
  const help = (AKM_HELP[a] || AKM_HELP[base] || '') + (a.startsWith('FT-') ? ' Fast-roaming variant.' : '');
  return `<span class="tag" title="${esc(help)}">${esc(a)}</span>`;
}

function wifiApRows(ex, d) {
  const a = ex && ex.ap;
  if (!a) return [];
  const rows = [], tags = xs => xs.join(' ');
  if (a.boot) {
    const secs = Math.max(0, Date.now() / 1000 - a.boot);
    rows.push(['Up for', `${dur(secs)} <span class="faint">(since ${dt(a.boot)}, estimated from the beacon timestamp; some access points reset it on their own)</span>`]);
  }
  if (a.rsn) {
    const r = a.rsn, bits = [...(r.akm || []).map(wifiAkmTag)];
    bits.push(`<span class="tag ${r.pmf === 'off' ? 'warn' : 'on'}" title="${esc(r.pmf === 'required' ? 'Management frame protection is required: clients ignore forged deauthentication and disassociation frames.' : r.pmf === 'optional' ? 'Management frame protection is supported but not required: older clients can still be kicked off with forged frames.' : 'No management frame protection: anyone nearby can disconnect clients with forged deauthentication frames.')}">PMF ${esc(r.pmf)}</span>`);
    if (r.transition) bits.push('<span class="tag warn" title="WPA3 and WPA2 on the same network: clients that connect with WPA2 get no WPA3 protection.">WPA3 + WPA2 transition</span>');
    if ((r.pairwise || []).includes('TKIP')) bits.push('<span class="tag warn" title="TKIP is an old cipher with known weaknesses.">TKIP</span>');
    rows.push(['Security details', `${tags(bits)} <span class="faint">${esc((r.pairwise || []).join(', '))}</span>`]);
  }
  if (a.wpa1) rows.push(['Old WPA', '<span class="tag warn" title="Also announces WPA version 1 (TKIP), the pre-WPA2 standard.">WPA 1 offered</span>']);
  if (a.load) rows.push(['Load', `${a.load.sta} connected · ${a.load.util}% of the time busy <span class="faint">(reported by the access point)</span>`]);
  if (a.ap_name) rows.push(['AP name', `${esc(a.ap_name)} <span class="faint">(announced in its beacons by ${esc(a.ap_name_src || 'the access point')}; an administrator can set it to anything)</span>`]);
  if (a.beacon_tu) rows.push(['Beacon interval', `${a.beacon_tu} TU <span class="faint">≈ ${Math.round(a.beacon_tu * 1.024)} ms</span>`]);
  if (a.country) rows.push(['Country', `${esc(a.country)}${a.country_env ? ` <span class="faint">(${esc(a.country_env)})</span>` : ''}`]);
  if (a.roaming && a.roaming.length) rows.push(['Roaming', tags(a.roaming.map(x => `<span class="tag" title="${esc(ROAM_HELP[x] || '')}">802.${esc(x)}</span>`))]);
  const gen = [];
  if (a.bss_color != null) gen.push(`<span class="tag" title="BSS colour: Wi-Fi 6 uses it to tell neighbouring networks on the same channel apart.">BSS colour ${a.bss_color}</span>`);
  if (a.mlo) gen.push('<span class="tag" title="Multi-link operation: this access point can use several bands at once (Wi-Fi 7).">multi-link (Wi-Fi 7)</span>');
  if (gen.length) rows.push(['Wi-Fi 6 / 7', tags(gen)]);
  const more = [];
  if (a.mbssid) more.push(['multiple BSSID (several networks from one radio)', 'One radio serves several networks, each with its own address, from a single set of beacons.']);
  if (a.interworking) more.push(['interworking / Hotspot', 'Announces Hotspot / interworking information, as carrier and public Wi-Fi does.']);
  if (a.ftm) more.push(['FTM location ranging', 'Answers fine timing measurement requests, so devices can work out their distance to it.']);
  if (a.beacon_protection) more.push(['beacon protection', 'Protects its beacons against forgery.']);
  if (a.mesh_id) more.push([`mesh “${a.mesh_id}”`, 'Part of an 802.11s mesh network with this mesh ID.']);
  (a.aruba || []).forEach(x => more.push([`Aruba ${x}`, 'An element Aruba access points add to their beacons.']));
  if (more.length) rows.push(['Also announces', more.map(([l, h]) => tagWithHelp(l, h)).join(' ')]);
  if (a.wps_configured != null || a.wps_locked) rows.push(['WPS', `${a.wps_configured ? 'configured' : 'not configured'}${a.wps_locked ? ' · <span class="warn-text">setup locked</span>' : ''}`]);
  if (a.rnr && a.rnr.length) rows.push(['Neighbouring APs', `<span class="faint">announced in its beacons (often the same device on another band):</span> ${a.rnr.map(n => `${devLink(n.bssid)} <span class="faint">ch ${n.ch}</span>`).join(', ')}`]);
  return rows;
}

function wifiClientRows(ex, d) {
  const rows = [];
  if (ex.rate_up != null || ex.rate_down != null) {
    rows.push(['Link rate', [ex.rate_up != null ? `↑ ${ex.rate_up} Mbit/s` : '', ex.rate_down != null ? `↓ ${ex.rate_down} Mbit/s` : ''].filter(Boolean).join(' &nbsp; ') + ' <span class="faint">(last data frame heard)</span>']);
  }
  if (ex.noise != null) rows.push(['Noise floor', `${ex.noise} dBm${d.last_rssi != null ? ` <span class="faint">· signal-to-noise ${d.last_rssi - ex.noise} dB</span>` : ''}`]);
  if (ex.same_as && ex.same_as.length) {
    rows.push(['Possibly the same device', `${ex.same_as.map(x => `${devLink(x.mac)} <span class="faint" title="The second address carried on the frame counter of the first, within seconds. Only a guess: other devices can match by chance.">counter +${x.step}</span>`).join(', ')}`]);
  }
  return rows;
}

function wifiFeaturesHtml(ci) {
  if (!ci) return '';
  const t = [...(ci.caps || [])];
  if (ci.dsss === false) t.push('no 802.11b rates');
  if (ci.chan_count) t.push(`${ci.chan_count} channels supported`);
  if (ci.txp) t.push(`TX power ${ci.txp[0]}–${ci.txp[1]} dBm`);
  if (!t.length) return '';
  return `<div style="margin-top:10px"><span class="faint small-text">What it says it can do: </span>${t.map(x => tagWithHelp(x, capHelp(x), 'margin:0 6px 6px 0')).join('')}</div>`;
}
