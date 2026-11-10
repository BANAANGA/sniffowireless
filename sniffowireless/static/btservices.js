'use strict';
/* Plain-language explanations of the Bluetooth services a device advertises (shown on hover).
   Standard 16-bit numbers are from the Bluetooth SIG assigned numbers; 0xFC00-0xFFFF are handed out to member companies. */

const BT_SERVICES = {
  '1800': ['Generic Access', 'Basic device name and appearance every Bluetooth LE device has.'],
  '1801': ['Generic Attribute', 'Lets other devices find out when the device’s list of services changes.'],
  '1802': ['Immediate Alert', 'Makes the device beep or flash on request, as used by “find my keys” style tags.'],
  '1803': ['Link Loss', 'Defines how the device alerts when the Bluetooth connection to its owner is lost.'],
  '1804': ['Tx Power', 'Reports the transmit power, which helps estimate distance.'],
  '1805': ['Current Time', 'Gives a connected device the current date and time (e.g. a phone setting a watch).'],
  '180a': ['Device Information', 'Manufacturer, model, serial number and firmware version.'],
  '180d': ['Heart Rate', 'A heart-rate sensor: chest strap, watch or fitness band.'],
  '180f': ['Battery', 'Reports the battery level.'],
  '1810': ['Blood Pressure', 'A blood pressure monitor.'],
  '1812': ['Human Interface Device (HID)', 'A keyboard, mouse, game controller or remote control.'],
  '1813': ['Scan Parameters', 'Lets a device tell its peripheral how often to advertise and scan, to save power.'],
  '1814': ['Running Speed & Cadence', 'A running pod or foot sensor.'],
  '1816': ['Cycling Speed & Cadence', 'A bicycle speed or cadence sensor.'],
  '1818': ['Cycling Power', 'A bicycle power meter.'],
  '1819': ['Location & Navigation', 'Position and navigation data, e.g. from a bike computer.'],
  '181a': ['Environmental Sensing', 'Temperature, humidity, pressure and similar sensor readings.'],
  '181b': ['Body Composition', 'A smart scale reporting body composition.'],
  '181c': ['User Data', 'Stores user profile data for health devices.'],
  '181d': ['Weight Scale', 'A weighing scale.'],
  '181e': ['Bond Management', 'Manages the pairings stored on the device.'],
  '181f': ['Continuous Glucose Monitoring', 'A continuous glucose monitor.'],
  '1820': ['Internet Protocol Support', 'Carries IPv6 over Bluetooth LE for IP-connected sensors.'],
  '1821': ['Indoor Positioning', 'Indoor location beacons.'],
  '1822': ['Pulse Oximeter', 'A blood-oxygen (SpO₂) sensor.'],
  '1823': ['HTTP Proxy', 'Lets a Bluetooth-only device make web requests through a gateway.'],
  '1824': ['Transport Discovery', 'Helps find which other transports (such as Wi-Fi) the device supports.'],
  '1825': ['Object Transfer', 'Transfers files or other objects.'],
  '1826': ['Fitness Machine', 'A treadmill, rower, indoor bike or other gym equipment.'],
  '1827': ['Mesh Provisioning', 'Used to add the device to a Bluetooth Mesh network (smart lighting, sensors).'],
  '1828': ['Mesh Proxy', 'Lets a phone talk to a Bluetooth Mesh network through this device.'],
  '1843': ['Audio Input Control', 'LE Audio: controls an audio input such as a microphone.'],
  '1844': ['Volume Control', 'LE Audio: remote volume control (Bluetooth 5.2 and newer).'],
  '1845': ['Volume Offset Control', 'LE Audio: balances volume between several outputs.'],
  '1846': ['Coordinated Set Identification', 'LE Audio: marks devices that work as a pair, such as left and right earbuds.'],
  '1847': ['Device Time', 'Keeps the clock of a device in sync.'],
  '1848': ['Media Control', 'LE Audio: play, pause and skip.'],
  '1849': ['Generic Media Control', 'LE Audio: the media controls of a device.'],
  '184e': ['Audio Stream Control', 'LE Audio: sets up the audio streams to earbuds, speakers or hearing aids.'],
  '184f': ['Broadcast Audio Scan', 'LE Audio: lets a receiver be told which broadcast (Auracast) to listen to.'],
  '1850': ['Published Audio Capabilities', 'LE Audio: lists the audio formats the device supports.'],
  '1851': ['Basic Audio Announcement', 'LE Audio: describes a broadcast audio stream.'],
  '1852': ['Broadcast Audio Announcement', 'LE Audio: the device is broadcasting audio (Auracast) that anyone nearby can tune in to.'],
  '1853': ['Common Audio', 'LE Audio: groups the audio services of one device.'],
  '1855': ['Telephony and Media Audio', 'LE Audio: call and media audio profile.'],
  '1856': ['Public Broadcast Announcement', 'LE Audio: an open (unencrypted) Auracast broadcast.'],
  // Bluetooth Classic profiles (older audio, phone and file-transfer devices).
  '1101': ['Serial Port', 'Bluetooth Classic: a wireless serial cable, used by adapters, GPS receivers and some gadgets.'],
  '1105': ['OBEX Object Push', 'Bluetooth Classic: receives files, contacts or calendar entries sent from another device.'],
  '1106': ['OBEX File Transfer', 'Bluetooth Classic: browse and copy files on the device.'],
  '1108': ['Headset', 'Bluetooth Classic: the older headset profile for calls.'],
  '110a': ['Audio Source (A2DP)', 'Bluetooth Classic: sends stereo music, as a phone or player does.'],
  '110b': ['Audio Sink (A2DP)', 'Bluetooth Classic: plays stereo music sent to it, as headphones and speakers do.'],
  '110c': ['A/V Remote Control Target', 'Bluetooth Classic: can be controlled with play, pause and skip commands.'],
  '110d': ['Advanced Audio Distribution (A2DP)', 'Bluetooth Classic: streaming of stereo music.'],
  '110e': ['A/V Remote Control', 'Bluetooth Classic: play, pause, skip and volume buttons.'],
  '110f': ['A/V Remote Control Controller', 'Bluetooth Classic: sends play, pause and skip commands to a player.'],
  '1112': ['Headset Audio Gateway', 'Bluetooth Classic: a phone or computer that connects calls to a headset.'],
  '1115': ['Personal Area Network User (PANU)', 'Bluetooth Classic: can use a network connection shared over Bluetooth.'],
  '1116': ['Network Access Point (NAP)', 'Bluetooth Classic: shares its network connection with Bluetooth devices (tethering).'],
  '1117': ['Group Ad-hoc Network (GN)', 'Bluetooth Classic: hosts a small Bluetooth network for a group of devices.'],
  '111e': ['Hands-Free', 'Bluetooth Classic: call audio and call control for a car kit or headset.'],
  '111f': ['Hands-Free Audio Gateway', 'Bluetooth Classic: a phone that connects calls to a car kit or headset.'],
  '1124': ['Human Interface Device (Classic)', 'Bluetooth Classic: a keyboard, mouse or game controller.'],
  '112d': ['SIM Access', 'Bluetooth Classic: lets a car kit use the phone’s SIM card.'],
  '112e': ['Phonebook Access Client', 'Bluetooth Classic: reads the phone’s contacts, as a car kit does.'],
  '112f': ['Phonebook Access Server', 'Bluetooth Classic: offers its contacts and call history to a car kit.'],
  '1132': ['Message Access Server', 'Bluetooth Classic: offers text messages to a car kit.'],
  '1133': ['Message Notification Server', 'Bluetooth Classic: tells a car kit that new messages arrived.'],
  '1134': ['Message Access Profile', 'Bluetooth Classic: reading text messages on a phone from another device.'],
  '1200': ['PnP Information', 'Bluetooth Classic: vendor, product and version identifiers of the device.'],
  '1203': ['Generic Audio', 'Bluetooth Classic: the device handles audio.'],
  // Services defined by companies (member UUIDs), as far as they are recognised.
  'fd6f': ['Exposure Notification', 'Contact-tracing beacon used by phones during the COVID-19 apps (Apple/Google).'],
  'fe2c': ['Google Fast Pair', 'Lets Android phones pair quickly with earbuds and speakers.'],
  'feaa': ['Eddystone', 'Google’s beacon format, used for location marketing and asset tags.'],
  'fd5a': ['Samsung SmartTag', 'Samsung’s item tracker.'],
  'feed': ['Tile', 'Tile item tracker.'],
  'feec': ['Tile', 'Tile item tracker.'],
  'fe95': ['Xiaomi', 'Xiaomi (MiBeacon) sensors, thermometers and smart-home gear.'],
  'fcd2': ['BTHome', 'An open format used by home-automation sensors (temperature, door contacts, buttons).'],
  'fe9f': ['Google', 'A service number registered by Google.'],
  'fe07': ['Sonos', 'Sonos speakers.'],
  'fe03': ['Amazon', 'A service number registered by Amazon (Echo, Fire devices).'],
  'fd44': ['Apple Find My network accessory', 'A tracker or accessory in Apple’s Find My network.'],
  'fe0f': ['Philips Hue', 'Philips Hue lights and accessories.'],
  'fe59': ['Nordic DFU', 'Firmware-update service of Nordic Semiconductor chips.'],
};

const BT_SERVICES_LONG = {
  '6e400001-b5a3-f393-e0a9-e50e24dcca9e': ['Nordic UART', 'A serial-style data channel over Bluetooth LE used by many hobby and Nordic-chip devices to send text or commands.'],
};

// Services worth a second look. Advertising one proves nothing about the device: whether it is a problem depends on
// pairing and authentication, which a passive listener cannot see.
const BT_RISK = {
  '1105': 'Accepts files and contacts pushed to it. Old phones with weak settings were open to “BlueSnarf” attacks through this.',
  '1106': 'Browsing and copying files. Should only work for a paired, trusted device.',
  '112d': 'Gives access to the SIM card. Should only be available to a paired car kit.',
  '112e': 'Reads contacts and call history. Should only work for a paired device.',
  '112f': 'Offers contacts and call history. Should only be available to a paired car kit.',
  '1132': 'Offers text messages. Should only be available to a paired device.',
  '1133': 'Announces new text messages. Should only go to a paired device.',
  '1134': 'Gives access to text messages. Should only be available to a paired device.',
  '1101': 'A serial port is often an unauthenticated back door on cheap gadgets and industrial adapters.',
  '1108': 'The old headset profile, replaced by Hands-Free. Suggests an old device that may not be updated.',
  '1124': 'A keyboard-type service: if it accepts connections without proper pairing, keystrokes can be injected.',
  '1802': 'Often lets anyone in range make the device beep or flash.',
  'fe59': 'Firmware update service. A risk only if updates are not signed or the service is not protected.',
  '1827': 'Mesh provisioning is open: the device can be added to a Bluetooth Mesh network. Check that this is intended.',
  '1828': 'A Bluetooth Mesh gateway: nearby phones can talk to the mesh through it.',
  '1115': 'Can use a network connection shared over Bluetooth.',
  '1116': 'Shares a network connection over Bluetooth. Check that this is intended.',
};

function btServiceInfo(u) {
  const k = String(u).toLowerCase();
  if (k.length > 4 && BT_SERVICES_LONG[k]) return { name: BT_SERVICES_LONG[k][0], text: BT_SERVICES_LONG[k][1], risk: null };
  if (k.length === 36) return { name: null, text: 'A vendor-specific (128-bit) service. Manufacturers use these for their own protocol, so the number alone does not say what the device does.', risk: null };
  if (k.length === 8) return { name: null, text: 'A 32-bit service number. Rarely used; the app does not recognise it.', risk: null };
  if (BT_SERVICES[k]) return { name: BT_SERVICES[k][0], text: BT_SERVICES[k][1], risk: BT_RISK[k] || null };
  const N = typeof BT_NUMBERS !== 'undefined' ? BT_NUMBERS : null;   // the SIG's assigned numbers (btnumbers.js)
  if (N && N.service[k]) return { name: N.service[k], text: 'A standard Bluetooth service (Bluetooth SIG Assigned Numbers). This app has no plain-language description of it yet.', risk: null };
  if (N && N.serviceClass[k]) return { name: N.serviceClass[k], text: 'A Bluetooth Classic profile or service class (Bluetooth SIG Assigned Numbers). This app has no plain-language description of it yet.', risk: null };
  if (N && N.member[k]) return { name: N.member[k], text: `This number is registered to ${N.member[k]}, a Bluetooth SIG member. What the device uses it for is up to that company; a device does not have to be made by them to use it.`, risk: null };
  if (N && N.sdo[k]) return { name: N.sdo[k], text: 'A number registered to a standards organisation (Bluetooth SIG Assigned Numbers).', risk: null };
  const n = parseInt(k, 16);
  if (N) return { name: null, text: 'This number is not in the Bluetooth SIG list shipped with this app: it may have been assigned since, or the device may be using a number nobody assigned.', risk: null };
  if (n >= 0xFC00 && n <= 0xFFFF) return { name: null, text: 'A service number assigned to a Bluetooth member company. This app does not know which one, and the device may use it for its own protocol.' };
  return { name: null, text: 'Not a service this app recognises. It may be a newer standard service or a vendor-specific one.' };
}

function btServiceTags(uuids) {
  return (uuids || []).map(u => {
    const i = btServiceInfo(u);
    const tip = `${u.length <= 8 ? '0x' : ''}${u}${i.name ? ' · ' + i.name : ''}\n${i.text}` + (i.risk ? `\n\nWorth a look: ${i.risk}\n(The device only advertises this service; the scan cannot tell whether it is protected.)` : '');
    return `<span class="svc${i.risk ? ' svc-risk' : ''}" tabindex="0" title="${esc(tip)}"><span class="mono">${esc(u)}</span>${i.name ? ` <span class="faint">${esc(i.name)}</span>` : ''}${i.risk ? ' <span class="svc-flag" aria-label="worth a look">⚠</span>' : ''}</span>`;
  }).join(', ');
}

function btFlagsText(f) {
  const parts = [];
  parts.push(f & 2 ? 'general discoverable' : f & 1 ? 'limited discoverable' : 'not discoverable');
  parts.push(f & 4 ? 'LE only (no classic Bluetooth)' : 'also supports classic Bluetooth');
  return esc(parts.join(' · '));
}

function btCompanyHtml(name) {
  if (/^Unregistered 0x/.test(name)) return `<span class="svc" tabindex="0" title="${esc('This number is not registered to any company (the Bluetooth SIG has assigned IDs only up to about 0x1116). The device most likely uses its own data format, so these bytes are not a company ID. See the raw data below.')}">${esc(name)}</span>`;
  if (/^Company 0x/.test(name)) return `<span class="svc" tabindex="0" title="${esc('An ID that is not in the Bluetooth SIG list shipped with this app. It may be a company registered after the list was made, or one the SIG has retired.')}">${esc(name)}</span>`;
  return esc(name);
}

function btRawMfgHtml(hex) {
  const b = (String(hex).match(/../g) || []);
  const id = b.length >= 2 ? `0x${b[1]}${b[0]}`.toUpperCase().replace('0X', '0x') : '';
  const tip = `The first 32 bytes of the manufacturer-specific data, as sent. ${id ? `The first two bytes (${b[0]} ${b[1]}) are the company ID field, read in reverse order: ${id}. ` : ''}The rest is whatever the manufacturer chose; on a device with an unregistered ID the first bytes may be part of its own format. Apple data is not kept here.`;
  return `<span class="mono svc" tabindex="0" title="${esc(tip)}" style="word-break:break-all">${esc(b.join(' '))}</span>`;
}
