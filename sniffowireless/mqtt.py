"""MQTT presence publish: arrived/left for devices you've labelled (Settings → Devices → label, or
marked "known") are published to an MQTT broker, retained, one topic per device — written with Home
Assistant's MQTT integration in mind, but it's plain MQTT, so anything that speaks it can use it.

Topics (under the configured prefix, "sniffowireless" by default):
  <prefix>/status             "online" while sniffowireless is connected to the broker, "offline"
                               otherwise (a Last Will the broker publishes on an unclean disconnect) —
                               a standard MQTT "availability" topic.
  <prefix>/presence/<mac>      JSON {"state": "home"|"away", "mac", "label", "name", "ts"}, retained,
                               published whenever a labelled device arrives or leaves.
  <prefix>/radio/<type>        JSON {"type", "id", "detail", "ts"}, not retained, for LoRa and Zigbee events:
                               lora_new_node, lora_flood, lora_join_flood, lora_fcnt_reset, zigbee_new_network,
                               zigbee_permit_join.
"""
import json
import logging
import queue
import threading
import time

log = logging.getLogger("sniffowireless.mqtt")

RADIO_EVENTS = ("lora_new_node", "lora_flood", "lora_join_flood", "lora_fcnt_reset", "zigbee_new_network", "zigbee_permit_join")


def _mac_topic(mac):
    return mac.replace(":", "")


class MqttPublisher:
    """A store.listeners callback (self.on_events); owns the broker connection, reconnecting as needed.
    Never blocks the store's writer thread: paho runs its own network thread, and publish() queues a
    message even while disconnected (sent once the connection is up)."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.client = None
        self.lock = threading.Lock()
        self.cfg = {}
        self.connected = False
        self.last_error = None
        self.q = queue.Queue(maxsize=10_000)  # decouples publishing (DB lookups + network) from the store's writer thread
        self.reload()
        ctx.settings.on_change(lambda k: self.reload() if k == "mqtt" else None)

    def start(self, stop):
        threading.Thread(target=self._run, args=(stop,), daemon=True, name="mqtt").start()

    def _run(self, stop):
        while not stop.is_set():
            try:
                events = self.q.get(timeout=1)
            except queue.Empty:
                continue
            try:
                self._publish(events)
            except Exception:
                log.exception("MQTT publish failed")

    # -------------------------------------------------------------- connection
    def reload(self):
        with self.lock:
            cfg = self.ctx.settings.get("mqtt")
            if cfg == self.cfg:
                return
            self.cfg = cfg
            self._disconnect()
            if cfg.get("enabled") and cfg.get("host"):
                self._connect()

    def _connect(self):
        try:
            import paho.mqtt.client as mqtt
        except ImportError:
            self.last_error = "paho-mqtt is not installed"
            log.error(self.last_error)
            return
        cfg = self.cfg
        c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="sniffowireless", clean_session=True)
        if cfg.get("username"):
            c.username_pw_set(cfg["username"], cfg.get("password") or None)
        if cfg.get("tls"):
            c.tls_set()
        status_topic = f"{cfg['topic_prefix']}/status"
        c.will_set(status_topic, "offline", qos=cfg.get("qos", 0), retain=True)
        c.on_connect = self._on_connect
        c.on_disconnect = self._on_disconnect
        self.client = c
        try:
            c.connect_async(cfg["host"], int(cfg.get("port") or 1883), keepalive=60)
            c.loop_start()
        except (OSError, ValueError) as e:
            self.last_error = str(e)
            log.warning("MQTT: could not start connecting to %s: %s", cfg["host"], e)

    def _disconnect(self):
        if self.client:
            try:
                self.client.loop_stop()
                self.client.disconnect()
            except Exception:
                pass
            self.client = None
        self.connected = False

    def _on_connect(self, client, userdata, flags, reason_code, properties=None):
        ok = reason_code == 0 or getattr(reason_code, "value", 0) == 0
        self.connected = ok
        self.last_error = None if ok else str(reason_code)
        if ok:
            client.publish(f"{self.cfg['topic_prefix']}/status", "online", qos=self.cfg.get("qos", 0), retain=True)
            log.info("MQTT: connected to %s:%s", self.cfg["host"], self.cfg.get("port") or 1883)
        else:
            log.warning("MQTT: connection to %s refused: %s", self.cfg.get("host"), reason_code)

    def _on_disconnect(self, client, userdata, flags, reason_code, properties=None):
        self.connected = False

    def status(self):
        with self.lock:
            cfg = self.cfg
        return {"enabled": bool(cfg.get("enabled")), "host": cfg.get("host") or "",
               "connected": self.connected, "last_error": self.last_error}

    # -------------------------------------------------------------- publish
    def on_events(self, events):
        """store.listeners callback: called on the store's writer thread on every flush. Only queues —
        the DB lookups and the actual publish happen on this module's own thread (_run), so a slow or
        unreachable broker can never hold up ingestion."""
        if not self.client or not self.connected:
            return
        presence = [e for e in events if e["type"] in ("arrived", "left") or e["type"] in RADIO_EVENTS]
        if not presence:
            return
        try:
            self.q.put_nowait(presence)
        except queue.Full:
            log.warning("MQTT queue full; dropping %d presence events", len(presence))

    def _publish_radio(self, events):
        """LoRa / Zigbee events (new node, flood, joining opened, ...) go out as they are, not retained: they are things that
        happened, not a state. Topic: <prefix>/radio/<event type>."""
        for e in events:
            try:
                self.client.publish(f"{self.cfg['topic_prefix']}/radio/{e['type']}",
                                    json.dumps({"type": e["type"], "id": e["mac"], "detail": e.get("detail"), "ts": e["ts"]}),
                                    qos=self.cfg.get("qos", 0), retain=False)
            except Exception:
                log.warning("MQTT: publish failed for %s", e["type"], exc_info=True)

    def _publish(self, events):
        self._publish_radio([e for e in events if e["type"] in RADIO_EVENTS])
        presence = [e for e in events if e["type"] in ("arrived", "left")]
        macs = {e["mac"] for e in presence}
        if not macs or not self._known(macs):
            return
        q = ",".join("?" * len(macs))
        meta = {r["mac"]: r for r in self.ctx.rows(
            f"SELECT mac, label, known FROM device_meta WHERE mac IN ({q}) AND (known=1 OR label IS NOT NULL)",
            list(macs))}
        names = {r["mac"]: r["name"] for r in self.ctx.rows(f"SELECT mac, name FROM devices WHERE mac IN ({q})", list(macs))}
        for e in presence:
            m = meta.get(e["mac"])
            if not m:  # not a device we publish presence for
                continue
            payload = {"state": "home" if e["type"] == "arrived" else "away", "mac": e["mac"],
                      "label": m.get("label"), "name": names.get(e["mac"]), "ts": e["ts"]}
            try:
                self.client.publish(f"{self.cfg['topic_prefix']}/presence/{_mac_topic(e['mac'])}",
                                    json.dumps(payload), qos=self.cfg.get("qos", 0), retain=self.cfg.get("retain", True))
            except Exception:
                log.warning("MQTT: publish failed for %s", e["mac"], exc_info=True)

    def _known(self, macs):
        """Cheap pre-check so a flush with no labelled/known devices in it skips the device_meta query."""
        q = ",".join("?" * len(macs))
        return bool(self.ctx.one(f"SELECT 1 FROM device_meta WHERE mac IN ({q}) AND (known=1 OR label IS NOT NULL) LIMIT 1",
                                 list(macs)))

    def test(self):
        """Settings 'Send test message' button: publish once, synchronously enough to report success/failure."""
        if not self.cfg.get("enabled") or not self.cfg.get("host"):
            raise ValueError("MQTT isn't enabled, or no broker host is set")
        if not self.client:
            raise ValueError("Not connected yet — check the host/port and try again in a few seconds")
        deadline = time.time() + 5
        while not self.connected and time.time() < deadline:
            time.sleep(0.2)
        if not self.connected:
            raise ValueError(self.last_error or "Could not connect to the broker")
        info = self.client.publish(f"{self.cfg['topic_prefix']}/status", "online", qos=self.cfg.get("qos", 0), retain=True)
        info.wait_for_publish(timeout=5)


# ------------------------------------------------------------------ web API
def routes(ctx):
    from fastapi import APIRouter, Depends, HTTPException
    from pydantic import BaseModel, Field

    from .auth import require_admin

    MASK = "••••••••"

    class MqttSettings(BaseModel):
        enabled: bool = False
        host: str = Field("", max_length=255)
        port: int = Field(1883, ge=1, le=65535)
        username: str = Field("", max_length=255)
        password: str = Field("", max_length=255)
        tls: bool = False
        topic_prefix: str = Field("sniffowireless", min_length=1, max_length=64, pattern=r"^[^\s+#]+$")
        qos: int = Field(0, ge=0, le=2)
        retain: bool = True

    r = APIRouter()

    @r.get("/api/settings/mqtt")
    def get_mqtt(_=Depends(require_admin)):
        cfg = dict(ctx.settings.get("mqtt"))
        if cfg.get("password"):
            cfg["password"] = MASK
        cfg["status"] = ctx.mqtt.status()
        return cfg

    @r.put("/api/settings/mqtt")
    def set_mqtt(body: MqttSettings, _=Depends(require_admin)):
        cur = ctx.settings.get("mqtt")
        new = body.model_dump()
        if new["password"] == MASK:
            new["password"] = cur.get("password") or ""
        ctx.settings.set("mqtt", new)  # on_change -> MqttPublisher.reload()
        return {"ok": True}

    @r.post("/api/settings/mqtt/test")
    def test_mqtt(_=Depends(require_admin)):
        try:
            ctx.mqtt.test()
        except ValueError as e:
            raise HTTPException(400, str(e))
        return {"ok": True}

    return r
