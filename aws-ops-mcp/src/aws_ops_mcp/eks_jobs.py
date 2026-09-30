"""Bounded background investigations with cooperative cancellation and evidence."""

import copy
import secrets
import threading
import time
from collections import OrderedDict
from datetime import datetime, timezone

from .config import ConfigurationError, resolve
from .contracts import bounded, encoded, envelope
from .eks_cli import CLI, CollectionError
from .eks_collect import Collector, pick


EXCLUSIONS = ["application functional tests", "active network probes", "effective IAM authorization evaluation",
              "historical CloudWatch metrics", "unknown third-party operators", "automatic remediation"]


class Investigations:
    def __init__(self, store, cli_factory=CLI, collector_factory=Collector, clock=time.monotonic):
        self.store, self.cli_factory, self.collector_factory, self.clock = store, cli_factory, collector_factory, clock
        self.jobs, self.lock = OrderedDict(), threading.RLock()

    def _expire(self):
        now = self.clock()
        for key in list(self.jobs):
            job = self.jobs[key]
            if job["finished"] is not None and now - job["finished"] > 900:
                del self.jobs[key]

    def start(self, account, region, clusters=None, log_target=None, inventory=False):
        result = envelope(account, region)
        try:
            config = resolve(account, region)
        except ConfigurationError:
            result.update(status="error", errors=[{"code": "configuration_invalid"}])
            result["coverage"]["complete"] = False
            return result
        with self.lock:
            self._expire()
            if sum(j["finished"] is None for j in self.jobs.values()) >= 2:
                result.update(status="error", errors=[{"code": "investigation_capacity_reached"}])
                result["coverage"]["complete"] = False
                return result
            while len(self.jobs) >= 20:
                key = next(k for k, j in self.jobs.items() if j["finished"] is not None)
                del self.jobs[key]
            key = secrets.token_urlsafe(24)
            job = {"id": key, "account": account, "region": region, "clusters": clusters or [],
                   "state": "running", "stop": threading.Event(), "finished": None,
                   "components": {}, "items": [], "findings": [], "errors": [], "remote": {},
                   "bytes": 0, "evidence_id": None, "local_identity": None, "started": self.clock()}
            job["collected_at"] = datetime.now(timezone.utc).isoformat()
            self.jobs[key] = job
            threading.Thread(target=self._run, args=(job, config, log_target, inventory), daemon=True).start()
        return self.get(key)

    def _emit(self, job, event):
        with self.lock:
            job["collected_at"] = datetime.now(timezone.utc).isoformat()
            if event["kind"] == "remote":
                job["remote"][event["command_id"]] = event
                return
            key = event["cluster"] + "/" + event["component"]
            job["components"][key] = event["coverage"]
            evidence = [{"kind": "coverage", "cluster": event["cluster"], "component": event["component"], **event["coverage"]}]
            evidence += event["items"]
            evidence += [{"kind": "finding", **finding} for finding in event["findings"]]
            for item in evidence:
                size = len(encoded(item))
                if size > 12000:
                    item = {"kind": "oversized_evidence", "cluster": event["cluster"], "component": event["component"]}
                    size = len(encoded(item))
                    job["errors"].append({"code": "evidence_item_limit"})
                if job["bytes"] + size > 4 * 1024 * 1024 or len(job["items"]) >= 10000:
                    if not any(e["code"] == "evidence_limit" for e in job["errors"]):
                        job["errors"].append({"code": "evidence_limit"})
                    break
                job["items"].append(item)
                job["bytes"] += size
            job["findings"].extend(event["findings"][:max(0, 1000 - len(job["findings"]))])

    def _run(self, job, config, log_target, inventory):
        try:
            cli = self.cli_factory(config, job["region"], stop=job["stop"], deadline=time.monotonic() + 1800)
            with self.lock:
                job["local_identity"] = pick(cli.identity, "Account Arn")
            emit = lambda event: self._emit(job, event)
            if inventory:
                count = 0
                for page in cli.pages("eks", "list-clusters", "clusters"):
                    for name in page:
                        cli.check()
                        if count >= 100:
                            raise CollectionError("cluster_limit")
                        try:
                            row = cli.call("eks", "describe-cluster", {"name": name})["cluster"]
                        except CollectionError as exc:
                            if exc.code in {"cancelled", "deadline_exceeded"}:
                                raise
                            emit({"kind": "component", "cluster": name, "component": "aws.inventory",
                                  "items": [], "findings": [], "coverage": {"complete": False, "observed": 0, "error": exc.code}})
                            count += 1
                            continue
                        emit({"kind": "component", "cluster": name, "component": "aws.inventory",
                              "items": [{"cluster": name, "kind": "cluster", "data": pick(row,
                                  "name arn status version platformVersion resourcesVpcConfig computeConfig")}],
                              "findings": [], "coverage": {"complete": True, "observed": 1}})
                        count += 1
                if not count:
                    emit({"kind": "component", "cluster": "inventory", "component": "aws.inventory",
                          "items": [], "findings": [], "coverage": {"complete": True, "observed": 0}})
            else:
                for cluster in job["clusters"]:
                    cli.check()
                    collector = self.collector_factory(cli, job["account"], cluster, emit)
                    try:
                        if log_target:
                            collector.cluster_data = cli.call("eks", "describe-cluster", {"name": cluster})["cluster"]
                        else:
                            collector.aws()
                        collector.kubernetes(log_target)
                    except CollectionError as exc:
                        if exc.code in {"cancelled", "deadline_exceeded", "ssm_submission_unconfirmed"}:
                            raise
                        collector.record("investigation", [], complete=False, code=exc.code)
                    except Exception:
                        collector.record("investigation", [], complete=False, code="collector_failed")
        except CollectionError as exc:
            with self.lock:
                job["errors"].append({"code": exc.code})
        except Exception:
            with self.lock:
                job["errors"].append({"code": "investigation_failed"})
        finally:
            with self.lock:
                job["state"] = "cancelled" if job["stop"].is_set() else "finished"
                job["finished"] = self.clock()
                job["items"].extend({"kind": "ssm_command", **event} for event in job["remote"].values())
                coverage = self._coverage(job)
                job["evidence_id"] = self.store.put(job["account"], job["region"], job["items"], coverage)
                if not job["evidence_id"]:
                    job["errors"].append({"code": "evidence_unavailable"})

    @staticmethod
    def _coverage(job):
        incomplete = sum(not c["complete"] for c in job["components"].values())
        unresolved = [r for r in job["remote"].values() if r["state"] not in {"Success", "Failed", "TimedOut", "Cancelled"}]
        return {"complete": bool(job["components"]) and not incomplete and not job["errors"]
                and job["finished"] is not None and job["state"] != "cancelled" and not unresolved,
                "components_observed": len(job["components"]), "components_incomplete": incomplete,
                "output_truncated": any(c.get("output_truncated") for c in job["components"].values()),
                "unconfirmed_remote_commands": len(unresolved), "excluded": EXCLUSIONS,
                "scope": "Only implemented checks; evidence lists component coverage. Not proof of overall application health."}

    def get(self, key):
        with self.lock:
            self._expire()
            if key not in self.jobs:
                result = envelope()
                result.update(status="error", errors=[{"code": "investigation_missing_or_expired"}])
                result["coverage"]["complete"] = False
                return result
            job = self.jobs[key]
            result = envelope(job["account"], job["region"])
            result["collected_at"] = job["collected_at"]
            result["coverage"] = self._coverage(job)
            result["investigation_id"] = key
            result["summary"] = {"state": job["state"], "clusters": job["clusters"],
                                 "local_identity": job["local_identity"], "evidence_items": len(job["items"]),
                                 "finding_count_retained": len(job["findings"]),
                                 "finding_count_reported": sum(c.get("finding_count", 0) for c in job["components"].values()),
                                 "next": "Poll eks_investigation_get; evidence available on completion" if job["finished"] is None else "Read evidence_get for details"}
            result["errors"] = copy.deepcopy(job["errors"][:20])
            result["findings"] = sorted(copy.deepcopy(job["findings"]), key=lambda f: {"error": 0, "warning": 1}.get(f.get("severity"), 2))
            result["items"] = [{"component": name, **coverage} for name, coverage in job["components"].items() if not coverage["complete"]][:20]
            if job["evidence_id"]:
                result["evidence_id"] = job["evidence_id"]
            if not result["coverage"]["complete"]:
                result["status"] = "partial" if job["components"] or job["finished"] is None else "error"
            elif (any(f.get("severity") in {"warning", "error"} for f in job["findings"])
                  or any(c.get("finding_severities", {}).get("warning", 0) + c.get("finding_severities", {}).get("error", 0)
                         for c in job["components"].values())):
                result["status"] = "degraded"
            return bounded(result)

    def cancel(self, key):
        with self.lock:
            if key in self.jobs and self.jobs[key]["finished"] is None:
                self.jobs[key]["stop"].set()
                self.jobs[key]["state"] = "cancelling"
        return self.get(key)
