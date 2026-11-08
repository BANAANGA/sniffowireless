"""Small helpers shared by API modules."""
import csv
import io
import math

from fastapi.responses import StreamingResponse

CSV_FORMULA = ("=", "+", "-", "@", "\t", "\r")


def csv_response(name, cols, data):
    """A CSV download. Cells that start like a spreadsheet formula get a leading quote: SSIDs and device names are chosen by strangers."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for r in data:
        w.writerow(["'" + v if isinstance(v, str) and v.startswith(CSV_FORMULA) else v for v in (r.get(c) for c in cols)])
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="{name}"'})


def overlap_counts(rows, since, until, bucket):
    """Count distinct macs whose [start, end] overlaps each time bucket."""
    n = max(1, math.ceil((until - since) / bucket))
    sets = [set() for _ in range(n)]
    for mac, start, end in rows:
        i0 = max(0, int((start - since) // bucket))
        i1 = min(n - 1, int((end - since) // bucket))
        for i in range(i0, i1 + 1):
            sets[i].add(mac)
    return [(since + i * bucket, len(s)) for i, s in enumerate(sets)]
