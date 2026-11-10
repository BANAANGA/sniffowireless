'use strict';
/* Hover explanations on the device page: what each row means, in plain language. Labels get a dotted underline and a tooltip
   (title), security names and capability tags get their own. Text is data here and goes through esc() when it is used. */

const LABEL_HELP = {
  // ---- every device
  'Address': 'The hardware (MAC) address the radio heard. A "randomized" address is made up by the device, changes from time to time and does not identify the device for long.',
  'Type': 'Which kind of radio this was heard on: a Wi-Fi access point or client, Bluetooth, or a device seen on the wired network.',
  'Vendor': 'The maker named by the first three bytes of a MAC address (the OUI). A device with a randomized address has none: the address says nothing about its maker.',
  'Signal (last / best)': 'Signal strength (RSSI) in dBm: closer to 0 is stronger. As a rough guide, -30 to -60 is strong, -60 to -75 is fair and below -80 is weak. Last is the latest reading, best the strongest ever heard.',
  'Frames': 'How many radio frames from this device have been counted since it was first seen.',
  'First seen': 'When this device was first heard by any sensor.',
  'Last seen': 'When this device was last heard.',
  'Room': 'The room of the sensor that hears this device best (set under Settings → Sensors).',
  'Time present': 'How long the device has been within range in total, and in how many visits. A visit ends when the device has been silent for a while.',
  'Average visit': 'The average length of one visit within range.',
  'Longest visit': 'The longest single visit within range.',
  'Time connected': 'How long it was connected to a network this system could see (it associated with an access point we heard), and in how many sessions.',
  'Connected now': 'It is connected to this network right now, according to the frames heard.',
  // ---- access points
  'SSID': 'The network name this access point broadcasts. "<hidden>" means it does not broadcast one: clients have to know it to connect.',
  'Channel': 'The radio channel and frequency it was heard on, with its band.',
  'Security': 'The encryption the network says it uses. Open means none; WPA2 and WPA3 are the current standards.',
  'Up for': 'How long the access point has been running, estimated from the timestamp in its beacons (its own timer). Some access points reset that timer without restarting.',
  'Security details': 'What the access point announces about how clients log in and how traffic is protected: key-management (password, WPA3 SAE, enterprise), ciphers, and whether management frames are protected (PMF).',
  'Old WPA': 'The network also offers WPA version 1 (TKIP), the standard that came before WPA2. It has known weaknesses.',
  'Load': 'How many stations are connected and how much of the time the channel is busy, as the access point itself reports it (the BSS Load element).',
  'Beacon interval': 'How often the access point announces itself. It is counted in TU (time units of 1.024 ms); 100 TU, about 102 ms, is typical.',
  'Country': 'The country whose radio rules the access point says it follows (the Country element). It decides which channels and power are allowed.',
  'Roaming': 'Standards that help clients move between access points: 802.11k (neighbour reports), 802.11v (the network can steer a client) and 802.11r (fast, secure hand-over).',
  'Wi-Fi 6 / 7': 'Wi-Fi 6 and 7 details from the beacon: the BSS colour tells neighbouring networks on one channel apart, multi-link operation lets a Wi-Fi 7 access point use several bands at once.',
  'Also announces': 'Other features in its beacons: several networks from one radio (multiple BSSID), Hotspot / interworking, location ranging (FTM), beacon protection, mesh.',
  'WPS': 'Wi-Fi Protected Setup, the easy-pairing feature. "Setup locked" means the access point has locked PIN setup, usually after failed attempts.',
  'Neighbouring APs': 'Other access points this one lists in its beacons (the Reduced Neighbor Report), often its own radios on another band.',
  'AP name': 'A name the access point announces in a vendor-specific element (Ubiquiti and Aruba do). An administrator can set it to anything.',
  // ---- clients
  'Link rate': 'The data rate of the last data frame heard, uplink (client to access point) and downlink. It shows what the link can do right now, not the internet speed.',
  'Noise floor': 'The background radio noise the receiver measured. The signal-to-noise ratio (signal minus noise) says how clean the link is: the higher, the better.',
  'Possibly the same device': 'Another randomized address whose frame counter carried straight on from this one within seconds. A guess only (optional feature): other devices can match by chance.',
  // ---- Bluetooth rows that sit in the same grid
  'Address type': 'How the Bluetooth address is formed: public (fixed, from the maker), random static, or private (changes regularly, which hides the device from tracking).',
  'TX power': 'The transmit power the device says it uses. With the signal strength it can help estimate distance.',
  'Advertised flags': 'Whether the device can be found by others (discoverable) and whether it also supports classic Bluetooth or only Bluetooth Low Energy.',
  'Advertising interval': 'How often the device sends its advertisement, estimated from how often it was heard.',
  'Preferred connection interval': 'The connection timing the device asks for when someone connects to it.',
  'Services': 'The Bluetooth services the device announces. Hover a number for what it is.',
  // ---- identification
  'Brand': 'The make, worked out from the evidence below (vendor, names, vendor elements). The coloured word is how sure it is.',
  'Model': 'The model, when a name, WPS information or another broadcast says so.',
  'Device type': 'What kind of device it probably is, from its capabilities, names and vendor.',
  'Operating system': 'The operating system, when a vendor element, a name or the pattern of its requests gives it away.',
  'Wi-Fi': 'The newest Wi-Fi standard the device supports, with its number of spatial streams (MIMO) and widest channel. See the explanation on the value.',
  'Wi-Fi chipset': 'The maker of the Wi-Fi chip, when a vendor-specific element names it.',
  'Estimated age': 'A device cannot be older than the newest Wi-Fi standard it supports, so that gives a lower bound; a known model gives its release year.',
  'Probe fingerprint': 'A short code for how the device builds its probe requests (the order and capabilities of what it lists). Devices of one model and software share it, so it can group the many random addresses one device uses.',
  'WPS info': 'What the device says about itself through Wi-Fi Protected Setup: manufacturer, model and name.',
};

// What a Wi-Fi generation is (the number on the box) and what the streams and width on the Wi-Fi row mean.
const GEN_HELP = {
  '3': 'Wi-Fi 3 or older (802.11a/b/g): no high-throughput capabilities advertised.',
  '4': 'Wi-Fi 4 (802.11n): up to 40 MHz channels and 4 streams; 2.4 and 5 GHz.',
  '5': 'Wi-Fi 5 (802.11ac): up to 160 MHz channels, 5 GHz.',
  '6': 'Wi-Fi 6 (802.11ax): more efficient with many devices (OFDMA); Wi-Fi 6E adds the 6 GHz band.',
  '7': 'Wi-Fi 7 (802.11be): up to 320 MHz channels and multi-link operation.',
};

function wifiRowHelp(value) {
  const m = /Wi-Fi (3|4|5|6|7)/.exec(String(value || ''));
  const base = m ? GEN_HELP[m[1]] + ' ' : '';
  return `${base}"4×4 MIMO" means four spatial streams (more streams, more speed and range); "160 MHz" is the widest channel it supports (wider is faster but needs more free spectrum).`;
}

// ---- security names
const ENC_BASE = {
  'OPN': 'Open network: no encryption. Anyone nearby can read the traffic.',
  'WEP': 'WEP: broken for many years and cracked in minutes. It should not be used.',
  'WPA': 'WPA (version 1, TKIP): outdated, with known weaknesses.',
  'WPA2': 'WPA2: AES encryption, the standard for years. Safe with a long, unique password.',
  'WPA3': 'WPA3: the newest standard; it also protects against offline password guessing.',
};
const ENC_SUFFIX = {
  'PSK': 'Everyone shares one password (WPA-Personal).',
  'SAE': 'WPA3-Personal: a password with the SAE handshake.',
  'MGT': 'Enterprise login: each user signs in, usually through a RADIUS server (802.1X).',
  'OWE': 'Opportunistic Wireless Encryption: encrypted without a password.',
};

function encHtml(enc) {
  if (!enc) return '—';
  return String(enc).split(',').map(tok => {
    const [base, suf] = tok.trim().split('/');
    const help = [ENC_BASE[base], suf ? ENC_SUFFIX[suf] : ''].filter(Boolean).join(' ');
    const bad = base === 'OPN' || base === 'WEP' || base === 'WPA';
    return `<span class="tag ${bad ? 'warn' : ''}"${help ? ` title="${esc(help)}"` : ''}>${esc(tok.trim())}</span>`;
  }).join(' ');
}

// ---- channel: band and the DFS note
function channelHelp(d) {
  const parts = ['The radio channel and frequency it was heard on.'];
  const ch = +d.channel;
  if (d.band === '2.4') parts.push('2.4 GHz: reaches far but is crowded; in most regions only channels 1, 6 and 11 do not overlap.');
  else if (d.band === '5') parts.push('5 GHz: faster and less crowded than 2.4 GHz, shorter range.');
  else if (d.band === '6') parts.push('6 GHz: the newest band (Wi-Fi 6E and 7), very little interference, shorter range.');
  if (d.band === '5' && ((ch >= 52 && ch <= 64) || (ch >= 100 && ch <= 144))) parts.push('A DFS channel: shared with weather and other radar, so an access point here must leave the channel when it hears radar.');
  return parts.join(' ');
}

// ---- capability tags and feature tags
const CAP_HELP = {
  '802.11v BSS transition': 'The network can suggest a better access point to this device (802.11v).',
  '802.11k radio measurement': 'It can report what it hears so the network can help it pick an access point (802.11k).',
  '802.11r fast roaming': 'Quick, secure hand-over between access points (802.11r).',
  'timing measurement': 'Supports measuring the time a frame takes, used for location.',
  'interworking': 'Can use Hotspot / Passpoint networks.',
  'TDLS': 'Can talk directly to another device on the same network (Tunneled Direct Link Setup).',
  'WNM notification': 'Accepts notifications from the network (WNM).',
  'operating mode notification': 'Can tell the access point how wide and how many streams it uses right now, to save power.',
  'FTM responder': 'Answers fine timing measurement requests, which let other devices work out their distance to it.',
  'FTM initiator': 'Can measure its distance to a device that answers fine timing measurement.',
  'FILS': 'Fast initial link setup: connects quicker.',
  'beacon protection': 'Protects the access point’s beacons against forgery.',
  'LDPC': 'A stronger error-correcting code, better at a weak signal.',
  'TX STBC': 'Sends the same data over two antennas for a more robust link (space-time block coding).',
  'RX STBC': 'Can receive that kind of two-antenna transmission.',
  'short GI 20 MHz': 'A shorter pause between symbols on a 20 MHz channel: a little more speed on a clean link.',
  'SU beamformee': 'Can be aimed at by an access point that focuses its signal on it (single-user beamforming).',
  'MU-MIMO beamformee': 'Can receive several streams meant for different devices at the same time (multi-user MIMO).',
  'beamformer': 'Can focus its own signal on another device.',
  'no 802.11b rates': 'It does not offer the oldest 802.11b speeds, which marks a modern device.',
};

const FEATURE_HELP = {
  'Wi-Fi Direct (P2P)': 'Can connect directly to other devices without an access point (screen casting, printing).',
  'MBO/OCE (agile multiband)': 'Multi-band operation: helps a device and network choose the best band. Common on newer phones.',
  'Hotspot 2.0 / Passpoint': 'Can join Hotspot 2.0 (Passpoint) networks automatically, such as carrier or roaming Wi-Fi.',
  'OWE transition': 'Supports encrypted open networks (OWE) next to a normal open one.',
  'OSEN': 'OSEN: an authentication used by Hotspot 2.0 online sign-up.',
};

function capHelp(label) {
  if (CAP_HELP[label]) return CAP_HELP[label];
  if (/ channels supported$/.test(label)) return 'How many channels it says it can use (the Supported Channels element).';
  if (/^TX power /.test(label)) return 'The lowest and highest transmit power it says it supports.';
  return '';
}
function featureHelp(label) {
  if (FEATURE_HELP[label]) return FEATURE_HELP[label];
  if (/^Aruba: /.test(label)) return 'An element Aruba access points add to their beacons.';
  return '';
}

// attributes for a label cell: a dotted underline and the tooltip, when there is one
function lblAttr(label) {
  const t = LABEL_HELP[label];
  return t ? ` class="hint" title="${esc(t)}"` : '';
}
function tagWithHelp(label, help, style = '') {
  return `<span class="tag"${style ? ` style="${style}"` : ''}${help ? ` title="${esc(help)}"` : ''}>${esc(label)}</span>`;
}
