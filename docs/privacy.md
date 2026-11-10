[← Back to the README](../README.md)

# Privacy and the law

sniffowireless listens to radio signals that people's phones, laptops, watches and gadgets send out all the time, and it keeps a record of what it hears. That is useful for looking after your own network, and it is also information about other people. **You are responsible for how you use it.** This page is general information, not legal advice; ask someone who knows the law where you live.

The red notice at the top of every page says the same in short. You can hide it until the browser session ends (the × on it); it comes back in a new tab or after the browser is closed.

## What it keeps

For every device it hears: its hardware (MAC) address, the maker, signal strength over time, when it was around, which networks it connected to or asked for, names it announces and what kind of device it probably is. The Ethernet and LAN features can also see which devices talk to which, and DNS lookups. None of this is the *content* of anyone's communication, and sniffowireless does not read or store it.

## Why it matters

- A MAC address identifies a device, and a device usually belongs to one person. In the EU and the UK regulators treat such identifiers as **personal data** under the GDPR in many cases, and other countries have similar rules. A record of when a person was in a place, or which networks their phone looked for, can be sensitive.
- Whether you may **monitor radio signals** in a place, **keep records** about other people's devices, or need to **tell people or ask for consent** depends on where you are, who the people are (family, guests, employees, passers-by) and what you do with it. Monitoring at work or in a shared building is often more restricted than at home.
- **Capturing the content** of other people's traffic, **joining or attacking** networks that are not yours, and **capturing handshakes of networks you are not responsible for** can be a criminal offence in many places. sniffowireless is passive, never sends attack frames, and only captures handshakes of networks you list under My networks; keep it that way.

## Good practice

- Have a clear, legitimate reason (security of your own network, your own home or office) and do not use it to follow, profile or identify individuals.
- Tell the people who are affected where that is expected or required: a notice at the entrance, a line in the house or office rules.
- Keep as little as you need, for as short a time as you need (below), and restrict who can open the interface (users and roles under Settings → Users).
- Do not share exports, screenshots or backups that show real addresses. Use the anonymised view for screenshots and demos.
- Answer requests from people to see or delete what you hold about them, where the law gives them that right: add the address to the Ignore list (Settings → Ignore list) and tick *Also delete data already stored for matching devices*, which also stops it being stored again. Settings → Clear data deletes by kind of radio.

## The tools in the application

Everything is under **Settings → Privacy** (admins).

| Tool | What it does |
|---|---|
| **Hashed storage** | Never stores a full static MAC address: it is replaced by a keyed pseudonym *before* it is written. Details below. |
| **Data retention** | How long each kind of data is kept (devices, signal history, events, sessions, probed networks, where a device was heard). Older data is deleted about once an hour. Settings → Modules has the limits for LAN, Zigbee and LoRa data. |
| **Anonymised view** | Shows pseudonyms for MAC addresses and / or SSIDs to everyone. Display only: the database keeps what it keeps. |
| **Ignore list** (Settings → Ignore list) | Devices, vendors and networks that are dropped before anything is stored. |
| **Clear data** (Settings → Clear data) | Deletes everything stored for one kind of radio. |

### Hashed storage in detail

With it on, `a4:83:e7:5c:21:0b` is stored as `a4:83:e7:<three bytes of a keyed hash>`. The first three bytes name the maker and stay, so vendor names, device types and statistics keep working. The same address always gets the same pseudonym, so a device is still recognised when it comes back; two addresses never get the same one. It happens at one place where every observation enters (local radios, remote sensors, the demo), and also inside text such as event details; addresses you type in the interface (a search, the ignore list, My networks) are turned into the same pseudonyms before they are saved. Log lines are scrubbed too. The tests check that the real address appears nowhere in the database file, its write-ahead log or the settings.

- **Which addresses:** *static* addresses (globally unique, the vendor part is real), which is what identifies a device for life. Randomised addresses, which phones already change on purpose, are left alone unless you choose *all*.
- **The key** is a file `privacy.key` in the data directory (mode 600), or the value of `PRIVACY_KEY`. It is created when the mode is first switched on and is **not** part of backups. Lose it and the pseudonyms of devices you see after that will differ from the old ones.
- **Existing data:** switching it on only affects what is stored from then on. *Hash the existing data* rewrites what is already in the database at the next start (all tables, including text and JSON), then compacts the file so the old values are gone. It can take a long time on a big database and needs free disk space about the size of the database. It cannot be undone, and **backups made earlier still hold the real addresses**.
- **Forced on:** `HASH_MACS=1` switches it on at start and the interface cannot switch it off.
- **Handshake capture is off** while it is on (a capture file contains the real addresses).
- **What it does not do:** it protects against a leaked or stolen database, backup, export or log. Someone who has both the database and the key can compute the pseudonym of any address they can guess (only 24 bits of an address are unknown once the vendor is known), and could confirm that a known device was seen. The radios still hear real addresses, remote sensors still send them to the server (use HTTPS), and the server keeps the real address of a device heard in the last 15 minutes in memory (never on disk) so that *play sound* and *read exact version* can still reach it. Randomised addresses, and addresses you write by hand in a label or note, are not touched. A partial address you search for is only found by its vendor part.

### Retention

Each kind of data has its own limit in days, or empty for the general `RETENTION_DAYS` (30 by default). Labelled, grouped and watched devices are not forgotten with the rest. A shorter time is the simplest way to hold less personal data; probed network names (where a person's phone has been) are a good candidate for a short limit.

## Remote sensors

A remote sensor sends what it hears to the server over the connection you set up, including real MAC addresses; the server hashes them when they arrive. Use HTTPS between them.
