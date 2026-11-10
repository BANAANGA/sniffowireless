"""A small flasher for ESP32-family chips (the Heltec V3's ESP32-S3), speaking the ROM bootloader's serial protocol, the one
esptool and the web flasher use. It only does what updating the LoRa sniffer firmware needs: reset the board into its
bootloader over the DTR/RTS lines, write one image at one address, check it by MD5 and restart the board. No dependencies besides
pyserial. The bootloader is in the chip's mask ROM, so a failed or interrupted write cannot brick the board: it can always be
flashed again (Settings -> LoRa flasher, or hold BOOT while pressing RST).

Protocol (ESP32 ROM, no stub): SLIP-framed packets  <dir=0 cmd len:u16 checksum:u32 data>  answered by  <dir=1 cmd len:u16 value:u32
data status:2+2>.  The ROM erases the whole range in FLASH_BEGIN, then takes the image in 1 KiB blocks."""
import hashlib
import struct
import time

SYNC, FLASH_BEGIN, FLASH_DATA, FLASH_END = 0x08, 0x02, 0x03, 0x04
SPI_SET_PARAMS, SPI_ATTACH, FLASH_MD5 = 0x0B, 0x0D, 0x13
BLOCK = 0x400
CHECKSUM_MAGIC = 0xEF
FLASH_SIZE = 8 * 1024 * 1024  # the Heltec V3's flash; the ROM only uses it to bound writes
END, ESC, ESC_END, ESC_ESC = 0xC0, 0xDB, 0xDC, 0xDD


class FlashError(Exception):
    pass


def slip_encode(packet):
    return bytes([END]) + packet.replace(b"\xdb", b"\xdb\xdd").replace(b"\xc0", b"\xdb\xdc") + bytes([END])


def checksum(data):
    c = CHECKSUM_MAGIC
    for b in data:
        c ^= b
    return c


class Loader:
    def __init__(self, port):
        self.port = port
        self.buf = bytearray()

    # ------------------------------------------------------------------ framing
    def _read_packet(self, deadline):
        """The next SLIP frame (unescaped), or None when `deadline` (monotonic) passes first."""
        frame, escaped, started = bytearray(), False, False
        while time.monotonic() < deadline:
            if not self.buf:
                self.port.timeout = max(0.01, min(0.2, deadline - time.monotonic()))
                self.buf += self.port.read(max(1, self.port.in_waiting))
                continue
            b = self.buf.pop(0)
            if b == END:
                if started and frame:
                    return bytes(frame)
                started, frame = True, bytearray()
            elif started:
                if escaped:
                    frame.append(END if b == ESC_END else ESC if b == ESC_ESC else b)
                    escaped = False
                elif b == ESC:
                    escaped = True
                else:
                    frame.append(b)
        return None

    def command(self, op, data=b"", chk=0, timeout=3.0, wait=True):
        self.port.write(slip_encode(struct.pack("<BBHI", 0, op, len(data), chk) + data))
        if not wait:
            return 0, b""
        deadline = time.monotonic() + timeout
        for _ in range(100):
            p = self._read_packet(deadline)
            if p is None:
                raise FlashError(f"no answer to command {op:#04x} within {timeout:g} s")
            if len(p) < 8:
                continue
            resp, op_ret, _, val = struct.unpack("<BBHI", p[:8])
            if resp == 1 and op_ret == op:
                return val, p[8:]
        raise FlashError("the bootloader's answers did not match the request")

    def check(self, what, op, data=b"", chk=0, timeout=3.0, resp_len=0):
        val, body = self.command(op, data, chk, timeout)
        if len(body) < resp_len + 2:
            raise FlashError(f"could not {what}: short answer")
        if body[resp_len] != 0:
            raise FlashError(f"could not {what} (bootloader error {body[resp_len + 1]:#04x})")
        return body[:resp_len] if resp_len else val

    # ------------------------------------------------------------------ bootloader
    def enter_bootloader(self, attempts=6):
        """Reset the chip with IO0 held low (the DTR/RTS circuit of the USB-serial bridge), then sync with the ROM."""
        last = "no answer"
        for i in range(attempts):
            self.port.dtr, self.port.rts = False, True   # EN low: chip in reset, IO0 high
            time.sleep(0.1)
            self.port.dtr, self.port.rts = True, False   # EN high, IO0 low: the chip boots into download mode
            time.sleep(0.05 + 0.05 * (i % 3))            # vary the timing a little between attempts
            self.port.dtr = False                        # IO0 high again
            self.buf.clear()
            self.port.reset_input_buffer()
            for _ in range(5):
                try:
                    self.command(SYNC, b"\x07\x07\x12\x20" + 32 * b"\x55", timeout=0.3)
                    for _ in range(7):  # the ROM answers a sync eight times: read the other seven
                        self._read_packet(time.monotonic() + 0.05)
                    return
                except FlashError as e:
                    last = str(e)
                    time.sleep(0.05)
        raise FlashError(f"the board did not enter its bootloader ({last}). Is it a Heltec V3 on this port?")

    def hard_reset(self):
        """Restart the chip into the firmware it has in flash."""
        self.port.dtr, self.port.rts = False, True
        time.sleep(0.1)
        self.port.rts = False

    def write_image(self, image, address=0, progress=None):
        size = len(image)
        if not size:
            raise FlashError("empty firmware image")
        self.check("attach the flash chip", SPI_ATTACH, struct.pack("<IBBBB", 0, 0, 0, 0, 0))
        self.check("set the flash parameters", SPI_SET_PARAMS, struct.pack("<IIIIII", 0, FLASH_SIZE, 64 * 1024, 4096, 256, 0xFFFF))
        blocks = (size + BLOCK - 1) // BLOCK
        # the ROM erases everything up front: roughly 40 s per MB at worst
        self.check("start the flash write", FLASH_BEGIN, struct.pack("<IIIII", size, blocks, BLOCK, address, 0),
                   timeout=max(3.0, 40.0 * size / 1e6))
        for seq in range(blocks):
            data = image[seq * BLOCK:(seq + 1) * BLOCK].ljust(BLOCK, b"\xff")
            for attempt in (0, 1, 2):
                try:
                    self.check(f"write block {seq}", FLASH_DATA, struct.pack("<IIII", BLOCK, seq, 0, 0) + data, checksum(data),
                               timeout=max(3.0, 40.0 * BLOCK / 1e6))
                    break
                except FlashError:
                    if attempt == 2:
                        raise
            if progress and (seq % 16 == 0 or seq == blocks - 1):
                progress((seq + 1) / blocks)
        got = self.check("verify the flash", FLASH_MD5, struct.pack("<IIII", address, size, 0, 0), timeout=max(3.0, 8.0 * size / 1e6),
                         resp_len=32).decode("ascii", "replace").lower()
        want = hashlib.md5(image, usedforsecurity=False).hexdigest()
        if got != want:
            raise FlashError(f"the board's flash does not match the image after writing (md5 {got[:8]}… instead of {want[:8]}…)")


def flash(path, image, address=0, baud=115200, progress=None, port_factory=None):
    """Write `image` to the board on serial port `path` and restart it. Raises FlashError with a sentence for the admin."""
    try:
        if port_factory:
            port = port_factory(path, baud)
        else:
            import serial
            port = serial.Serial(path, baud, timeout=0.2, rtscts=False, dsrdtr=False, xonxoff=False)
    except Exception as e:
        raise FlashError(f"could not open {path}: {e}")
    try:
        loader = Loader(port)
        loader.enter_bootloader()
        loader.write_image(image, address, progress)
        loader.hard_reset()
    except FlashError:
        raise
    except Exception as e:  # a serial error halfway: the board is still in its bootloader and can be flashed again
        raise FlashError(f"serial error while flashing: {e}")
    finally:
        try:
            port.close()
        except Exception:
            pass
