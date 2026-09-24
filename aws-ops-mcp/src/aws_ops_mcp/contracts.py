"""Versioned response envelope and wire-size budget."""

import json
from datetime import datetime, timezone


def encoded(value) -> bytes:
    # Default separators conservatively match SDK JSON serialization overhead.
    return json.dumps(value, ensure_ascii=True).encode("utf-8")


def envelope(account=None, region=None):
    return {
        "schema_version": "1.0", "account": account, "region": region,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "status": "ok", "summary": {}, "findings": [],
        "coverage": {"complete": True, "output_truncated": False}, "errors": [],
    }


def bounded(result, limit=12 * 1024):
    for field in ("findings", "items"):
        if len(result.get(field, [])) > 20:
            result[field] = result[field][:20]
            result["coverage"]["output_truncated"] = True
    while len(encoded(result)) > limit:
        field = next((name for name in ("items", "findings") if result.get(name)), None)
        if field is None:
            raise ValueError("Response metadata exceeded budget")
        result[field].pop()
        result["coverage"]["output_truncated"] = True
    return result
