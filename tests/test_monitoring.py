import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_dashboard_only_uses_metrics_that_exist_and_has_no_overlapping_panels():
    d = json.loads((ROOT / "contrib" / "monitoring" / "grafana" / "dashboards" / "sniffowireless.json").read_text())
    source = (ROOT / "sniffowireless" / "metrics.py").read_text()
    names = {m for p in d["panels"] for t in p.get("targets", []) for m in re.findall(r"sniffowireless_[a-z0-9_]+", t["expr"])}
    assert {"sniffowireless_lora_nodes_active", "sniffowireless_lora_packets_1h", "sniffowireless_lora_airtime_seconds_1h",
            "sniffowireless_zigbee_radios_active", "sniffowireless_zigbee_networks"} <= names
    for n in names:
        assert f'"{n}"' in source, f"{n} is not exported by metrics.py"
    ids = [p["id"] for p in d["panels"]]
    assert len(ids) == len(set(ids))
    cells = set()
    for p in d["panels"]:
        g = p["gridPos"]
        mine = {(x, y) for x in range(g["x"], g["x"] + g["w"]) for y in range(g["y"], g["y"] + g["h"])}
        assert not mine & cells, p["title"]
        cells |= mine
