"""The firmware flasher against a simulated ESP32 ROM bootloader, and the update flow around it (sensor pause, remote request, API)."""
import hashlib
import struct
import threading
import time

import pytest
from fastapi.testclient import TestClient

from sniffowireless import adapters, espflash, status
from sniffowireless.auth import hash_password
from sniffowireless.config import Config
from sniffowireless.espflash import FlashError, Loader, slip_encode
from sniffowireless.lora import LoraSensor
from sniffowireless.main import build
from sniffowireless.web import create_app


class FakeChip:
    """A serial port with an ESP32 ROM bootloader behind it: it syncs after the DTR/RTS reset sequence, erases and writes on
    FLASH_BEGIN/FLASH_DATA, and answers FLASH_MD5."""

    def __init__(self, bootable=True, corrupt=False, reject_first_block=False, status_bytes=4):
        self.bootable, self.corrupt, self.reject_first_block, self.status_bytes = bootable, corrupt, reject_first_block, status_bytes
        self._dtr = self._rts = False
        self.in_boot = False
        self.rx = bytearray()      # bytes the host wrote, not yet parsed
        self.out = bytearray()     # bytes waiting for the host to read
        self.flash = {}            # address -> byte
        self.begun = None
        self.timeout = 0.2
        self.resets = []
        self.closed = False
        self.rejected = 0
        self.attached = self.params = False

    # the DTR/RTS lines (the USB-serial bridge turns them into IO0 and EN)
    @property
    def dtr(self): return self._dtr

    @dtr.setter
    def dtr(self, v):
        self._dtr = v
        self._lines()

    @property
    def rts(self): return self._rts

    @rts.setter
    def rts(self, v):
        self._rts = v
        self._lines()

    def _lines(self):
        if self._dtr and not self._rts and self.bootable:  # EN released while IO0 is low: download mode
            self.in_boot = True
        elif self._rts and not self._dtr:                   # EN low
            self.resets.append("reset")
            self.in_boot = False

    in_waiting = property(lambda self: len(self.out))

    def reset_input_buffer(self):
        self.out.clear()

    def close(self):
        self.closed = True

    def write(self, data):
        self.rx += data
        while True:
            try:
                a = self.rx.index(0xC0)
                b = self.rx.index(0xC0, a + 1)
            except ValueError:
                return
            frame, self.rx = bytes(self.rx[a + 1:b]), self.rx[b + 1:]
            if frame and self.in_boot:
                self._handle(frame.replace(b"\xdb\xdc", b"\xc0").replace(b"\xdb\xdd", b"\xdb"))

    def read(self, n):
        if not self.out:
            time.sleep(min(self.timeout, 0.005))
            return b""
        data, self.out = bytes(self.out[:n]), self.out[n:]
        return data

    def _reply(self, op, value=0, data=b"", fail=None):
        st = bytes([1, fail]) + b"\x00\x00" if fail else b"\x00\x00\x00\x00"
        body = data + st[:self.status_bytes]
        self.out += slip_encode(struct.pack("<BBHI", 1, op, len(body), value) + body)

    def _handle(self, p):
        _, op, ln, chk = struct.unpack("<BBHI", p[:8])
        data = p[8:8 + ln]
        if op == espflash.SYNC:
            for _ in range(8):
                self._reply(op, 0x12345678)
        elif op == espflash.SPI_ATTACH:
            self.attached = len(data) == 8
            self._reply(op)
        elif op == espflash.SPI_SET_PARAMS:
            self.params = len(data) == 24
            self._reply(op)
        elif op == espflash.FLASH_BEGIN:
            size, blocks, bsize, addr, enc = struct.unpack("<IIIII", data)
            assert self.attached and self.params and bsize == 0x400 and blocks == (size + 0x3FF) // 0x400
            self.begun = (size, addr)
            self._reply(op)
        elif op == espflash.FLASH_DATA:
            n, seq, _, _ = struct.unpack("<IIII", data[:16])
            block = data[16:]
            if len(block) != n or espflash.checksum(block) != chk:
                return self._reply(op, fail=0x07)
            if self.reject_first_block and seq == 0 and not self.rejected:
                self.rejected += 1
                return self._reply(op, fail=0x05)
            base = self.begun[1] + seq * 0x400
            for i, b in enumerate(block):
                self.flash[base + i] = b
            self._reply(op)
        elif op == espflash.FLASH_MD5:
            addr, size, _, _ = struct.unpack("<IIII", data)
            content = bytes(self.flash.get(addr + i, 0xFF) for i in range(size))
            if self.corrupt:
                content = bytes([content[0] ^ 0xFF]) + content[1:]
            self._reply(op, data=hashlib.md5(content).hexdigest().encode())
        else:
            self._reply(op, fail=0x05)

    def image(self, addr, size):
        return bytes(self.flash.get(addr + i, 0xFF) for i in range(size))


IMAGE = bytes(range(256)) * 9 + b"\xc0\xdb\xc0\xdb\xdd\xdc" * 20 + b"tail"   # SLIP's special bytes in the middle, and not a whole block


def test_flashes_an_image_and_verifies_it():
    chip = FakeChip()
    seen = []
    espflash.flash("/dev/ttyUSB9", IMAGE, progress=seen.append, port_factory=lambda p, b: chip)
    assert chip.image(0, len(IMAGE)) == IMAGE and chip.begun == (len(IMAGE), 0)
    assert seen[-1] == 1.0 and seen == sorted(seen)
    assert chip.closed and chip.in_boot is False and chip.resets.count("reset") >= 2   # reset into the bootloader, and out again


def test_flashes_at_an_address_and_copes_with_two_status_bytes():
    chip = FakeChip(status_bytes=2)
    espflash.flash("x", b"hello firmware", address=0x10000, port_factory=lambda p, b: chip)
    assert chip.image(0x10000, 14) == b"hello firmware" and chip.begun == (14, 0x10000)


def test_a_rejected_block_is_sent_again():
    chip = FakeChip(reject_first_block=True)
    espflash.flash("x", IMAGE, port_factory=lambda p, b: chip)
    assert chip.rejected == 1 and chip.image(0, len(IMAGE)) == IMAGE


def test_a_wrong_checksum_after_writing_is_an_error():
    with pytest.raises(FlashError, match="does not match"):
        espflash.flash("x", IMAGE, port_factory=lambda p, b: FakeChip(corrupt=True))


def test_a_board_that_does_not_enter_the_bootloader(monkeypatch):
    chip = FakeChip(bootable=False)
    monkeypatch.setattr(Loader, "enter_bootloader", lambda self, attempts=6, orig=Loader.enter_bootloader: orig(self, attempts=1))
    with pytest.raises(FlashError, match="did not enter its bootloader"):
        espflash.flash("x", IMAGE, port_factory=lambda p, b: chip)
    assert chip.closed and not chip.flash


def test_port_errors_become_flash_errors():
    def boom(p, b):
        raise OSError("No such file or directory")
    with pytest.raises(FlashError, match="could not open"):
        espflash.flash("/dev/nope", IMAGE, port_factory=boom)
    with pytest.raises(FlashError, match="empty"):
        espflash.flash("x", b"", port_factory=lambda p, b: FakeChip())


# ------------------------------------------------------------------ the sensor steps aside while the board is written
class Quiet:
    def __init__(self):
        self.closed = threading.Event()

    def write_line(self, t):
        pass

    def read_line(self, timeout):
        time.sleep(min(timeout, 0.02))
        return "PONG" if not self.closed.is_set() else (_ for _ in ()).throw(OSError("closed"))

    def close(self):
        self.closed.set()


def test_the_capture_loop_gives_up_the_port_during_an_update_and_comes_back(monkeypatch):
    from sniffowireless import lora as lora_mod
    monkeypatch.setattr(lora_mod, "RETRY_INTERVAL", 0.2)
    status.SENSORS.clear()
    opened = []

    def factory(path):
        opened.append(time.monotonic())
        return Quiet()
    s = LoraSensor("/dev/ttyFLASH1", Config(), [], link_factory=factory)
    monkeypatch.setattr(s, "handshake", lambda link: (_ for _ in ()).throw(lora_mod.LoraError("test: no handshake")) if False else "PONG")
    monkeypatch.setattr(s, "run", lambda link: (link.closed.wait(5), (_ for _ in ()).throw(OSError("link closed"))))
    stop = threading.Event()
    s.start(stop)
    time.sleep(0.3)
    assert len(opened) == 1
    got = {}

    def fake_flasher(path, image, progress=None):
        got["path"], got["image"], got["opened_during"] = path, image, len(opened)
        progress(0.5)
        assert status.SENSORS[s.name]["state"] == "updating" and "50%" in status.SENSORS[s.name]["note"]
        time.sleep(0.5)  # the loop must not have the port open meanwhile
        got["opened_after_wait"] = len(opened)
    s.flash(b"IMG", flasher=fake_flasher)
    assert got["path"] == "/dev/ttyFLASH1" and got["image"] == b"IMG"
    assert got["opened_during"] == got["opened_after_wait"] == 1
    assert "Firmware updated" in status.SENSORS[s.name]["note"]
    time.sleep(0.6)
    assert len(opened) == 2                                # and it opens the board again afterwards
    stop.set()
    for t in threading.enumerate():
        if t.name == s.name:
            t.join(3)
    status.SENSORS.pop(s.name, None)


def test_a_second_update_while_one_runs_is_refused():
    s = LoraSensor("/dev/ttyFLASH2", Config(), [], link_factory=lambda p: Quiet())
    s.stop = threading.Event()
    s.flashing.set()
    with pytest.raises(FlashError, match="already running"):
        s.flash(b"x", flasher=lambda *a, **k: None)


# ------------------------------------------------------------------ asking for it: local board, remote sensor, API
PW = "correct-horse-battery"


@pytest.fixture
def ctx(tmp_path):
    status.SENSORS.clear()
    adapters.PENDING.clear()
    adapters.REGISTRY.clear()
    c = build(Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path)))
    with c.wdb() as w:
        for name, role in (("admin", "admin"), ("view", "viewer")):
            w.execute("INSERT INTO users(username, pw_hash, role, created) VALUES(?, ?, ?, 0)", (name, hash_password(PW, iterations=1000), role))
    return c


def client(ctx, user="admin"):
    c = TestClient(create_app(ctx), base_url="http://sniffowireless.test", headers={"x-sniffowireless": "1"})
    assert c.post("/api/auth/login", json={"username": user, "password": PW}).status_code == 200
    return c


def test_flashing_a_local_board_from_the_api(ctx, monkeypatch):
    done = threading.Event()
    got = {}
    s = LoraSensor("/dev/ttyUSB7", Config(), [], link_factory=lambda p: Quiet())
    monkeypatch.setattr(s, "flash", lambda image, **k: (got.setdefault("n", len(image)), done.set()))
    r = client(ctx).post("/api/lora/flash", json={"name": s.name})
    assert r.status_code == 200 and r.json()["started"] and done.wait(3) and got["n"] > 100_000      # the image that ships with the build
    assert client(ctx).post("/api/lora/flash", json={"name": "lora:nothing"}).status_code == 404
    assert client(ctx).post("/api/lora/flash", json={"name": "wifi:wlan0"}).status_code == 400
    assert client(ctx, "view").post("/api/lora/flash", json={"name": s.name}).status_code == 403
    s.flashing.set()
    assert client(ctx).post("/api/lora/flash", json={"name": s.name}).status_code == 409


def test_a_remote_sensor_is_asked_and_downloads_the_image_with_its_own_token(ctx):
    a = client(ctx)
    status.replace_remote("garage", [{"name": "lora:ttyUSB0", "type": "lora", "state": "listening"}], time.time())
    r = a.post("/api/lora/flash", json={"sensor": "garage", "name": "lora:ttyUSB0"})
    assert r.status_code == 200 and r.json()["queued"]
    cmd, = adapters.take("garage")
    from sniffowireless.lora import firmware_manifest
    m = firmware_manifest()
    assert cmd == {"action": "flash", "name": "lora:ttyUSB0", "version": m["version"], "sha256": m["sha256"], "size": m["size"]}
    assert a.post("/api/lora/flash", json={"sensor": "nobody", "name": "lora:ttyUSB0"}).status_code == 404
    # the image endpoint is for sensor tokens only
    assert a.get("/api/ingest/firmware").status_code == 401
    _, token = ctx.auth.create_token("garage", "sensor", "garage")
    c = TestClient(create_app(ctx), base_url="http://sniffowireless.test")
    r = c.get("/api/ingest/firmware", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200 and hashlib.sha256(r.content).hexdigest() == m["sha256"]
    assert c.get("/api/lora/firmware.bin", headers={"Authorization": f"Bearer {token}"}).status_code == 403


def test_the_sensor_checks_the_image_before_flashing(ctx, monkeypatch):
    s = LoraSensor("/dev/ttyUSB6", Config(), [], link_factory=lambda p: Quiet())
    wrote = []
    monkeypatch.setattr(s, "flash", lambda image, **k: wrote.append(image))
    good = b"firmware-bytes"
    cmd = {"action": "flash", "name": s.name, "version": 3, "sha256": hashlib.sha256(good).hexdigest(), "size": len(good)}
    adapters.run_commands([cmd], lambda: good)
    time.sleep(0.3)
    assert wrote == [good]
    adapters.run_commands([{**cmd, "sha256": "0" * 64}], lambda: good)                    # not what the server announced
    adapters.run_commands([{**cmd, "name": "lora:../../x"}], lambda: good)                # not a board name
    adapters.run_commands([cmd], None)                                                    # a sensor that cannot download does nothing
    time.sleep(0.3)
    assert wrote == [good] and "does not match" in status.SENSORS.get(s.name, {}).get("note", "does not match")


def test_a_failed_update_is_reported_on_the_board(ctx, monkeypatch):
    s = LoraSensor("/dev/ttyUSB5", Config(), [], link_factory=lambda p: Quiet())

    def fail(image, **k):
        raise FlashError("the board did not enter its bootloader")
    monkeypatch.setattr(s, "flash", fail)
    with pytest.raises(FlashError):
        adapters.flash_lora(s.name, b"x")
    assert status.SENSORS[s.name]["state"] == "error" and "bootloader" in status.SENSORS[s.name]["error"]
