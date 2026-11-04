"""Host and process resource figures for the overview: CPU load, memory, database and disk size (Linux /proc).

CPU percentages are measured between two calls (the overview polls), so the first call reports none.
"""
import os
import shutil
import threading
import time

_lock = threading.Lock()
_prev = {}  # last /proc/stat and process-time sample


def _read(path):
    try:
        with open(path) as fh:
            return fh.read()
    except OSError:
        return ""


def _cpu_times():
    line = _read("/proc/stat").split("\n", 1)[0].split()
    if not line or line[0] != "cpu":
        return None
    v = [int(x) for x in line[1:]]
    idle = v[3] + (v[4] if len(v) > 4 else 0)  # idle + iowait
    return sum(v[:8]), idle


def _meminfo():
    out = {}
    for ln in _read("/proc/meminfo").splitlines():
        k, _, rest = ln.partition(":")
        if rest.strip().endswith("kB"):
            out[k] = int(rest.split()[0]) * 1024
    return out


def _rss():
    for ln in _read("/proc/self/status").splitlines():
        if ln.startswith("VmRSS:"):
            return int(ln.split()[1]) * 1024
    return None


def _size(path):
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def snapshot(db_path, data_dir):
    now = time.monotonic()
    cpu, proc = _cpu_times(), os.times()
    proc_cpu = proc.user + proc.system
    cores = os.cpu_count() or 1
    with _lock:
        p = _prev.copy()
        if p and now - p["t"] < 1.0:  # several pollers: reuse the last reading instead of a noisy tiny interval
            host_pct, sniffowireless_pct = p.get("host_pct"), p.get("sniffowireless_pct")
        else:
            host_pct = sniffowireless_pct = None
            if p and cpu and p.get("cpu"):
                dt, didle = cpu[0] - p["cpu"][0], cpu[1] - p["cpu"][1]
                if dt > 0:
                    host_pct = round(100 * (1 - didle / dt), 1)
            if p:
                sniffowireless_pct = round(100 * (proc_cpu - p["proc"]) / (now - p["t"]) / cores, 1)
            _prev.update({"t": now, "cpu": cpu, "proc": proc_cpu, "host_pct": host_pct, "sniffowireless_pct": sniffowireless_pct})
    try:
        load = os.getloadavg()
    except OSError:
        load = None
    mem = _meminfo()
    total = mem.get("MemTotal")
    avail = mem.get("MemAvailable", mem.get("MemFree"))
    db = _size(db_path)
    wal = _size(db_path + "-wal")
    try:
        disk = shutil.disk_usage(data_dir)
        disk = {"total": disk.total, "used": disk.used, "free": disk.free}
    except OSError:
        disk = None
    return {
        "cpu": {"percent": host_pct, "sniffowireless_percent": sniffowireless_pct, "cores": cores,
                "load": [round(x, 2) for x in load] if load else None},
        "memory": {"total": total, "used": total - avail if total and avail is not None else None, "sniffowireless_rss": _rss()},
        "db": {"bytes": db + wal, "main": db, "wal": wal},
        "disk": disk,
    }
