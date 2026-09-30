"""Standalone, standard-library-only recipe executed on a Linux SSM bastion.

The controller prepends eks_kubernetes.py and sets PAYLOAD before calling main().
"""

import json
import base64
import os
import re
import subprocess
import tempfile
import time
import zlib
from urllib.parse import quote

if "PATHS" not in globals():
    from .eks_kubernetes import PATHS, analyze, normalize


def execute(args, env, text=False):
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        try:
            process = subprocess.run(args, env=env, stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=20)
        except (OSError, subprocess.TimeoutExpired):
            raise RuntimeError("remote_dependency_or_timeout") from None
        err.seek(0)
        error = err.read(8192).decode("utf-8", errors="replace")
        if process.returncode:
            code = "remote_command_failed"
            for marker, value in (("Forbidden", "kubernetes_forbidden"), ("Unauthorized", "kubernetes_unauthorized"),
                                  ("NotFound", "api_not_found"), ("could not find", "api_not_found"),
                                  ("AccessDenied", "remote_aws_access_denied"), ("ExpiredToken", "remote_credentials_expired"),
                                  ("timeout", "kubernetes_timeout"), ("no such host", "dns_unavailable")):
                if marker.lower() in error.lower():
                    code = value
                    break
            raise RuntimeError(code)
        out.seek(0)
        raw = out.read(4 * 1024 * 1024 + 1)
    if len(raw) > 4 * 1024 * 1024:
        raise RuntimeError("remote_output_limit")
    return raw.decode("utf-8", errors="replace") if text else json.loads(raw)


def remote_collect(payload):
    env = dict(os.environ)
    env.update(AWS_PAGER="", AWS_CLI_AUTO_PROMPT="off", AWS_MAX_ATTEMPTS="2",
               AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="true")
    aws = ["aws", "--region", payload["region"], "--output", "json", "--cli-connect-timeout", "3", "--cli-read-timeout", "10"]
    identity = execute(aws + ["sts", "get-caller-identity"], env)
    if identity.get("Account") != payload["account_id"]:
        raise RuntimeError("remote_account_mismatch")
    if payload.get("expected_identity_arn") and identity.get("Arn") != payload["expected_identity_arn"]:
        raise RuntimeError("remote_identity_mismatch")
    cluster = execute(aws + ["eks", "describe-cluster", "--name", payload["cluster"]], env)["cluster"]
    if cluster.get("arn") != payload["cluster_arn"]:
        raise RuntimeError("remote_cluster_mismatch")
    if not cluster.get("endpoint", "").startswith("https://") or not cluster.get("certificateAuthority", {}).get("data"):
        raise RuntimeError("cluster_endpoint_invalid")
    result = {"identity": {"account": identity["Account"], "arn": identity["Arn"]},
              "cluster_arn": cluster["arn"], "items": [], "findings": [], "complete": True,
              "output_truncated": False, "observed": 0, "finding_count": 0, "finding_severities": {},
              "authentication_role": payload.get("role_arn")}
    token_args = ["eks", "get-token", "--cluster-name", payload["cluster"], "--region", payload["region"]]
    if payload.get("role_arn"):
        token_args += ["--role-arn", payload["role_arn"]]
    with tempfile.TemporaryDirectory(prefix="aws-ops-eks-") as directory:
        path = os.path.join(directory, "config.json")
        config = {"apiVersion": "v1", "kind": "Config", "current-context": "diagnostic",
                  "clusters": [{"name": "target", "cluster": {"server": cluster["endpoint"],
                     "certificate-authority-data": cluster["certificateAuthority"]["data"]}}],
                  "contexts": [{"name": "diagnostic", "context": {"cluster": "target", "user": "diagnostic"}}],
                  "users": [{"name": "diagnostic", "user": {"exec": {
                      "apiVersion": "client.authentication.k8s.io/v1beta1", "command": "aws", "args": token_args,
                      "interactiveMode": "Never"}}}]}
        with open(path, "w", encoding="utf-8") as stream:
            json.dump(config, stream)
        os.chmod(path, 0o600)
        kubectl = ["kubectl", "--kubeconfig", path, "--request-timeout=15s"]
        if payload["kind"] == "logs":
            target = payload["log_target"]
            args = kubectl + ["logs", target["pod"], "-n", target["namespace"], "-c", target["container"],
                              "--since=10m", "--tail=100", "--limit-bytes=10000", "--timestamps=true"]
            text = execute(args, env, text=True)
            text = re.sub(r"(?:AKIA|ASIA)[A-Z0-9]{16}", "[REDACTED_ACCESS_KEY]", text)
            text = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", text)
            text = re.sub(r'''(?i)((?:aws_(?:secret_access_key|session_token)|authorization|password|client_secret|secret|token|api[_-]?key)["']?\s*[:=]\s*["']?)([^"'\s,;]+)''',
                          r"\1[REDACTED]", text)
            text = re.sub(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "[REDACTED_JWT]", text)
            result["items"] = [{"kind": "logs", **target, "text": text,
                                "scope": "last 10m, at most 100 lines and 10000 bytes; redaction best effort"}]
            result["observed"] = 1
        else:
            kind, cursor, seen = payload["kind"], payload.get("page_token", ""), set()
            deadline = time.monotonic() + 100
            for _ in range(1 if payload.get("paged") else 20):
                url = PATHS[kind] + "?limit=" + str(payload.get("page_size", 100))
                if kind == "events":
                    url += "&fieldSelector=type%3DWarning"
                if cursor:
                    url += "&continue=" + quote(cursor, safe="")
                elif payload.get("resource_version"):
                    url += "&resourceVersion=" + quote(payload["resource_version"], safe="") + "&resourceVersionMatch=Exact"
                try:
                    page = execute(kubectl + ["get", "--raw", url], env)
                except RuntimeError as exc:
                    result.update(complete=False, error=str(exc))
                    break
                for obj in page.get("items", []):
                    item = normalize(kind, obj)
                    findings = analyze(item)
                    result["observed"] += 1
                    result["finding_count"] += len(findings)
                    for finding in findings:
                        severity = finding["severity"]
                        result["finding_severities"][severity] = result["finding_severities"].get(severity, 0) + 1
                    if len(result["items"]) < 2000:
                        result["items"].append(item)
                    else:
                        result["output_truncated"] = True
                    if len(result["findings"]) < 2000:
                        result["findings"].extend(findings[:2000 - len(result["findings"])])
                    if result["finding_count"] > len(result["findings"]):
                        result["output_truncated"] = True
                cursor = page.get("metadata", {}).get("continue")
                result["next_token"] = cursor
                result["resource_version"] = page.get("metadata", {}).get("resourceVersion")
                if payload.get("paged"):
                    break
                if not cursor:
                    break
                if cursor in seen or time.monotonic() >= deadline:
                    result.update(complete=False, error="remote_collection_limit")
                    break
                seen.add(cursor)
            else:
                result.update(complete=False, error="remote_page_limit")
    return result


def pack_result(result):
    """Compress normalized evidence before applying the SSM stdout budget."""
    while True:
        raw = json.dumps(result, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        wire = json.dumps({"encoding": "zlib-base64-v1", "payload": base64.b64encode(zlib.compress(raw)).decode("ascii")})
        if len(wire) <= 18000 and len(raw) <= 4 * 1024 * 1024:
            return wire
        # Rare oversized collections remain explicit partial evidence; never loop per byte.
        field = "items" if result.get("items") else "findings"
        if not result.get(field):
            return json.dumps({"complete": False, "error": "remote_metadata_limit", "items": [], "findings": []})
        result[field] = result[field][:len(result[field]) // 2]
        result["output_truncated"] = True


def main(payload):
    try:
        result = remote_collect(payload)
    except RuntimeError as exc:
        result = {"complete": False, "error": str(exc), "items": [], "findings": [], "observed": 0}
    except Exception:
        result = {"complete": False, "error": "remote_collection_failed", "items": [], "findings": [], "observed": 0}
    print(pack_result(result))
