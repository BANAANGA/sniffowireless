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

function btServiceInfo(u) {
  const k = String(u).toLowerCase();
  if (BT_SERVICES[k]) return { name: BT_SERVICES[k][0], text: BT_SERVICES[k][1] };
  const n = parseInt(k, 16);
  if (n >= 0xFC00 && n <= 0xFFFF) return { name: null, text: 'A service number assigned to a Bluetooth member company. This app does not know which one, and the device may use it for its own protocol.' };
  return { name: null, text: 'Not a service this app recognises. It may be a newer standard service or a vendor-specific one.' };
}

function btServiceTags(uuids) {
  return (uuids || []).map(u => {
    const i = btServiceInfo(u);
    return `<span class="svc" tabindex="0" title="${esc(`0x${u}${i.name ? ' · ' + i.name : ''}\n${i.text}`)}"><span class="mono">${esc(u)}</span>${i.name ? ` <span class="faint">${esc(i.name)}</span>` : ''}</span>`;
  }).join(', ');
}
