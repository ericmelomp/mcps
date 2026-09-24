"""EC2 collection and deterministic checks, independent of MCP."""

from .aws import error_code


def text(value):
    return str(value)[:128] if value is not None else None


def normalize(instance, health=False):
    state = instance.get("InstanceState" if health else "State", {}).get("Name", "unknown")
    item = {"instance_id": text(instance.get("InstanceId")), "state": text(state)}
    if not health:
        item.update(instance_type=text(instance.get("InstanceType")),
                    availability_zone=text(instance.get("Placement", {}).get("AvailabilityZone")),
                    lifecycle=text(instance.get("InstanceLifecycle", "on-demand")))
    else:
        item["checks"] = {
            "instance": text(instance.get("InstanceStatus", {}).get("Status", "unavailable")),
            "system": text(instance.get("SystemStatus", {}).get("Status", "unavailable")),
        }
        if "AttachedEbsStatus" in instance:
            item["checks"]["attached_ebs"] = text(instance["AttachedEbsStatus"].get("Status", "unavailable"))
        events = [event for event in instance.get("Events", [])
                  if not event.get("Description", "").startswith("[Completed]")]
        item["events"] = [{"code": text(event.get("Code")), "not_before": text(event.get("NotBefore"))}
                          for event in events[:20]]
        item["events_truncated"] = len(events) > 20
    return item


def collect(client, health, emit, max_pages=100):
    operation = "describe_instance_status" if health else "describe_instances"
    args = {"MaxResults": 100}
    if health:
        args["IncludeAllInstances"] = True
    seen = set()
    try:
        for _ in range(max_pages):
            response = getattr(client, operation)(**args)
            raw = response.get("InstanceStatuses", []) if health else [
                instance for reservation in response.get("Reservations", [])
                for instance in reservation.get("Instances", [])
            ]
            token = response.get("NextToken")
            emit({"kind": "page", "items": [normalize(item, health) for item in raw], "complete": not bool(token)})
            if not token:
                return
            if token in seen:
                emit({"kind": "error", "code": "pagination_cycle"})
                return
            seen.add(token)
            args["NextToken"] = token
        emit({"kind": "error", "code": "page_limit"})
    except Exception as exc:
        emit({"kind": "error", "code": error_code(exc)})


def analyze(items):
    findings, unavailable = [], set()
    for item in items:
        iid = item["instance_id"]
        checks = item["checks"]
        if item["state"] == "running":
            failed = [name for name, value in checks.items() if value == "impaired"]
            unknown = [name for name, value in checks.items() if value not in {"ok", "impaired"}
                       and not (name == "attached_ebs" and value == "not-applicable")]
            if failed:
                findings.append({"instance_id": iid, "code": "status_check_failed", "checks": failed})
            if unknown:
                unavailable.add(iid)
                findings.append({"instance_id": iid, "code": "status_check_unavailable", "checks": unknown})
        elif item["state"] not in {"stopped", "stopping", "shutting-down", "terminated"}:
            unavailable.add(iid)
            findings.append({"instance_id": iid, "code": "state_not_assessable", "state": item["state"]})
        if item["events"]:
            findings.append({"instance_id": iid, "code": "scheduled_events", "events": item["events"]})
        if item["events_truncated"]:
            unavailable.add(iid)
    return findings, len(unavailable)
