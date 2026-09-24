"""Orchestrate configuration, collection, analysis and evidence."""

from collections import Counter

from . import runner
from .config import ConfigurationError, resolve
from .contracts import bounded, envelope
from .ec2 import analyze
from .evidence import EvidenceStore


class Service:
    def __init__(self, store=None, run=None):
        self.store = store if store is not None else EvidenceStore()
        self.run = run if run is not None else runner.run

    def query(self, account, region, health=False):
        result = envelope(account, region)
        try:
            config = resolve(account, region)
        except ConfigurationError:
            result.update(status="error", errors=[{"code": "configuration_invalid", "hint": "Check AWS_OPS_CONFIG, alias and allowed region"}])
            result["coverage"]["complete"] = False
            return result
        items, errors, pages, complete = self.run(config, region, health)
        findings, unavailable = analyze(items) if health else ([], 0)
        result["summary"] = {
            "observed_instances": len(items), "counts_complete": complete,
            "states": dict(Counter(item["state"] for item in items)),
            "finding_count": len(findings), "unassessable_instances": unavailable,
        }
        result["coverage"].update(
            complete=complete and unavailable == 0,
            pagination_complete=complete, pages=pages, examined_items=len(items),
            analyses=["ec2_state", "ec2_status_checks", "ec2_scheduled_events"] if health else ["ec2_inventory"],
            scope="One account and region; excludes application health, network tests and historical metrics",
        )
        if not complete:
            result["status"] = "partial" if pages else "error"
        elif unavailable:
            result["status"] = "partial"
        elif findings:
            result["status"] = "degraded"
        result["errors"] = errors
        result["findings"] = findings
        result["items"] = items[:20]
        if len(items) > 20:
            result["coverage"]["output_truncated"] = True
        if items:
            evidence_id = self.store.put(account, region, items, result["coverage"])
            if evidence_id:
                result["evidence_id"] = evidence_id
            else:
                result["coverage"]["evidence_unavailable"] = True
        return bounded(result)
