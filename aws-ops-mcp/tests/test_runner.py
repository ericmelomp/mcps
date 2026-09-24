import time

from aws_ops_mcp.config import Account
from aws_ops_mcp.runner import run


def slow_worker(connection, account, region, health):
    connection.send({"kind": "page", "items": [{"instance_id": "i-1", "state": "running"}], "complete": False})
    time.sleep(30)


def large_worker(connection, account, region, health):
    connection.send({"kind": "page", "items": [{"instance_id": f"i-{i}"} for i in range(3)], "complete": True})
    connection.close()


def test_deadline_kills_worker_and_retains_evidence():
    start = time.monotonic()
    items, errors, pages, complete = run(Account(account_id="000000000000", regions=["us-east-1"]),
                                        "us-east-1", False, timeout=3, target=slow_worker)
    assert time.monotonic() - start < 7
    assert items[0]["instance_id"] == "i-1"
    assert errors == [{"code": "timeout"}]
    assert pages == 1 and not complete


def test_item_limit_never_reports_complete():
    items, errors, _, complete = run(Account(account_id="000000000000", regions=["us-east-1"]),
                                     "us-east-1", False, target=large_worker, max_items=2)
    assert len(items) == 2
    assert errors == [{"code": "item_limit"}]
    assert not complete
