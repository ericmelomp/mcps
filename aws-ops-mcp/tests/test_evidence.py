from aws_ops_mcp.evidence import EvidenceStore
from aws_ops_mcp.contracts import encoded


def test_expiration_and_eviction():
    now = [0]
    store = EvidenceStore(ttl=10, max_queries=1, clock=lambda: now[0])
    old = store.put("one", "us-east-1", [{"instance_id": "i-1"}], {"complete": True})
    new = store.put("two", "us-east-1", [{"instance_id": "i-2"}], {"complete": True})
    assert store.get(old)["status"] == "error"
    assert store.get(new)["account"] == "two"
    now[0] = 11
    assert store.get(new)["status"] == "error"
    assert store.size == 0


def test_evidence_byte_capacity_and_copy_isolation():
    store = EvidenceStore(max_bytes=500)
    items = [{"id": "first"}]
    key = store.put("a", "r", items, {"complete": False})
    items[0]["id"] = "mutated"
    page = store.get(key)
    assert page["status"] == "partial"
    assert page["items"][0]["id"] == "first"
    assert store.put("a", "r", [{"x": "x" * 1000}], {"complete": True}) is None


def test_byte_limited_pages_make_progress_without_skipping_items():
    store = EvidenceStore()
    items = [{"id": i, "events": [{"code": "x" * 128}] * 20} for i in range(30)]
    key = store.put("a", "r", items, {"complete": True, "output_truncated": False})
    seen, offset = [], 0
    while offset is not None:
        page = store.get(key, offset)
        assert len(encoded(page)) <= 24576
        assert page["items"]
        seen.extend(item["id"] for item in page["items"])
        offset = page["next_offset"]
    assert seen == list(range(30))
