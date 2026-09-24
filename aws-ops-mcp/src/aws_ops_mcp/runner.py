"""Isolate AWS credential providers and API calls under a hard deadline."""

import multiprocessing
import time

from .aws import ec2_client, error_code
from .config import Account
from .ec2 import collect


def worker(connection, account, region, health):
    try:
        client = ec2_client(Account.model_validate(account), region)
        collect(client, health, connection.send)
    except Exception as exc:
        connection.send({"kind": "error", "code": error_code(exc)})
    finally:
        connection.close()


def run(account, region, health, timeout=60, target=worker, max_items=10000):
    context = multiprocessing.get_context("spawn")
    receive, send = context.Pipe(duplex=False)
    process = context.Process(target=target, args=(send, account.model_dump(), region, health), daemon=True)
    deadline = time.monotonic() + timeout
    items, errors, pages, complete = {}, [], 0, False
    try:
        process.start()
        send.close()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not receive.poll(max(0, remaining)):
                errors.append({"code": "timeout"})
                complete = False
                break
            try:
                message = receive.recv()
            except EOFError:
                break
            if message["kind"] == "error":
                errors.append({"code": message["code"]})
                complete = False
                break
            pages += 1
            for item in message["items"]:
                if len(items) >= max_items and item["instance_id"] not in items:
                    errors.append({"code": "item_limit"})
                    break
                items[item["instance_id"]] = item
            complete = message["complete"] and not errors
            if errors or complete:
                break
        if not complete and not errors:
            errors.append({"code": "worker_incomplete"})
    except Exception:
        complete = False
        errors.append({"code": "worker_error"})
    finally:
        receive.close()
        send.close()
        if process.pid is not None:
            if process.is_alive():
                process.terminate()
            process.join(timeout=1)
            if process.is_alive():
                process.kill()
                process.join(timeout=1)
            process.close()
    return list(items.values()), errors, pages, complete
