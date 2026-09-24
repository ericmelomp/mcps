"""Bounded per-process evidence cache, safe for concurrent tool calls."""

import copy
import secrets
import threading
import time
from collections import OrderedDict

from .contracts import encoded, envelope


class EvidenceStore:
    def __init__(self, ttl=900, max_queries=100, max_bytes=20 * 1024 * 1024, clock=time.monotonic):
        self.ttl, self.max_queries, self.max_bytes = ttl, max_queries, max_bytes
        self.clock = clock
        self.entries = OrderedDict()
        self.lock = threading.Lock()
        self.size = 0

    def _drop(self, key):
        self.size -= self.entries.pop(key)[3]

    def _expire(self):
        now = self.clock()
        for key in list(self.entries):
            if self.entries[key][0] <= now:
                self._drop(key)

    def put(self, account, region, items, coverage):
        payload = copy.deepcopy({"account": account, "region": region, "items": items, "coverage": coverage})
        size = len(encoded(payload))
        if size > self.max_bytes:
            return None
        with self.lock:
            self._expire()
            while self.entries and (len(self.entries) >= self.max_queries or self.size + size > self.max_bytes):
                self._drop(next(iter(self.entries)))
            key = secrets.token_urlsafe(24)
            self.entries[key] = (self.clock() + self.ttl, payload, len(items), size)
            self.size += size
            return key

    def get(self, key, offset=0, limit=50):
        result = envelope()
        with self.lock:
            self._expire()
            entry = self.entries.get(key)
            if entry is None:
                result.update(status="error", errors=[{"code": "evidence_missing_or_expired"}])
                result["coverage"]["complete"] = False
                return result
            _, payload, total, _ = entry
            result.update(account=payload["account"], region=payload["region"], evidence_id=key)
            result["coverage"] = copy.deepcopy(payload["coverage"])
            if not result["coverage"]["complete"]:
                result["status"] = "partial"
            result["items"] = copy.deepcopy(payload["items"][offset:offset + min(limit, 50)])
            result["summary"] = {"available_items": total, "offset": offset}
            result["next_offset"] = offset + len(result["items"]) if offset + len(result["items"]) < total else None
            while len(encoded(result)) > 24 * 1024 and result["items"]:
                result["items"].pop()
                result["coverage"]["output_truncated"] = True
                result["next_offset"] = offset + len(result["items"])
            return result
