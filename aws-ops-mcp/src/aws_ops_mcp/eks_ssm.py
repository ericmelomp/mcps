"""Explicit cluster-to-bastion mapping and fixed SSM recipes."""

import json
import base64
import binascii
import os
import re
import secrets
import time
import zlib
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from .eks_cli import CollectionError


class Bastion(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    account: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")
    region: str = Field(pattern=r"^[a-z]{2}(?:-[a-z]+)+-\d+$")
    cluster: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,99}$")
    instance_id: str = Field(pattern=r"^i-(?:[0-9a-f]{8}|[0-9a-f]{17})$")
    role_arn: str | None = Field(default=None, pattern=r"^arn:aws(?:-cn|-us-gov)?:iam::\d{12}:role/[\w+=,.@/-]+$")
    expected_identity_arn: str | None = Field(default=None, max_length=2048,
        pattern=r"^arn:aws(?:-cn|-us-gov)?:(?:sts|iam)::\d{12}:[\w+=,.@/-]+$")


def resolve_bastion(account, region, cluster):
    try:
        data = json.loads(Path(os.environ["AWS_OPS_EKS_CONFIG"]).read_text(encoding="utf-8-sig"))
        if set(data) != {"bastions"} or not isinstance(data["bastions"], list) or len(data["bastions"]) > 100:
            raise ValueError()
        matches = [Bastion.model_validate(row) for row in data["bastions"]]
        matches = [b for b in matches if (b.account, b.region, b.cluster) == (account, region, cluster)]
        if len(matches) != 1:
            raise ValueError()
        return matches[0]
    except (OSError, ValueError, KeyError, TypeError):
        raise CollectionError("bastion_mapping_missing_or_invalid") from None


def recipe(payload):
    directory = Path(__file__).parent
    source = (directory / "eks_kubernetes.py").read_text(encoding="utf-8")
    source += "\n" + (directory / "eks_remote.py").read_text(encoding="utf-8")
    # JSON is nested in a Python string literal, never interpolated into shell syntax.
    source += "\nmain(json.loads(" + repr(json.dumps(payload)) + "))\n"
    return "python3 - <<'AWS_OPS_EKS_RECIPE'\n" + source + "\nAWS_OPS_EKS_RECIPE"


def validate_bastion(cli, bastion):
    result = cli.call("ssm", "describe-instance-information", {
        "Filters": [{"Key": "InstanceIds", "Values": [bastion.instance_id]}]})
    rows = result.get("InstanceInformationList", [])
    if len(rows) != 1 or rows[0].get("PingStatus") != "Online" or rows[0].get("PlatformType") != "Linux":
        raise CollectionError("bastion_not_online_linux")


def decode_result(text):
    """Decode bounded SSM output without allowing decompression bombs or trailing streams."""
    if len(text) > 24000:
        raise ValueError("ssm_output_limit")
    result = json.loads(text)
    if isinstance(result, dict) and result.get("encoding") == "zlib-base64-v1":
        try:
            compressed = base64.b64decode(result["payload"], validate=True)
            decoder = zlib.decompressobj()
            raw = decoder.decompress(compressed, 4 * 1024 * 1024 + 1)
            if len(raw) > 4 * 1024 * 1024 or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
                raise ValueError("ssm_decompression_limit")
            result = json.loads(raw)
        except (binascii.Error, zlib.error) as exc:
            raise ValueError("ssm_encoding_invalid") from exc
    if not isinstance(result, dict) or not isinstance(result.get("items"), list) or not isinstance(result.get("complete"), bool):
        raise ValueError("ssm_result_invalid")
    return result


def run_recipe(cli, bastion, payload, emit):
    payload = dict(payload, role_arn=bastion.role_arn, expected_identity_arn=bastion.expected_identity_arn)
    command_id, terminal = None, False
    try:
        try:
            response = cli.call("ssm", "send-command", {
            "InstanceIds": [bastion.instance_id], "DocumentName": "AWS-RunShellScript",
            "TimeoutSeconds": 60, "Parameters": {"commands": [recipe(payload)], "executionTimeout": ["180"]},
            "Comment": "AWS Ops MCP fixed EKS diagnostic recipe",
            })
        except CollectionError as exc:
            if exc.code in {"aws_cli_timeout", "aws_cli_failed", "aws_cli_unavailable"}:
                emit({"kind": "remote", "command_id": "unknown-" + secrets.token_hex(8),
                      "instance_id": bastion.instance_id, "state": "submission_unconfirmed"})
                raise CollectionError("ssm_submission_unconfirmed") from None
            raise
        command_id = response["Command"]["CommandId"]
        if not re.fullmatch(r"[0-9a-fA-F-]{36}", command_id):
            raise CollectionError("ssm_response_invalid")
        emit({"kind": "remote", "command_id": command_id, "instance_id": bastion.instance_id, "state": "running"})
        deadline = min(cli.deadline, time.monotonic() + 240)
        while time.monotonic() < deadline:
            cli.check()
            try:
                response = cli.call("ssm", "get-command-invocation", {"CommandId": command_id, "InstanceId": bastion.instance_id})
            except CollectionError as exc:
                if exc.code != "invocation_pending":
                    raise
                response = {"Status": "Pending"}
            status = response.get("Status")
            if status in {"Success", "Failed", "TimedOut", "Cancelled"}:
                terminal = True
                emit({"kind": "remote", "command_id": command_id, "instance_id": bastion.instance_id, "state": status})
                if status != "Success" or response.get("ResponseCode") != 0:
                    raise CollectionError("ssm_command_" + status.lower())
                try:
                    return decode_result(response["StandardOutputContent"])
                except (ValueError, KeyError, TypeError):
                    raise CollectionError("ssm_output_invalid_or_truncated") from None
            if cli.stop:
                cli.stop.wait(2)
            else:
                time.sleep(2)
        raise CollectionError("ssm_wait_timeout")
    finally:
        if command_id and not terminal:
            state = "cancellation_unconfirmed"
            try:
                cli.call("ssm", "cancel-command", {"CommandId": command_id, "InstanceIds": [bastion.instance_id]}, cleanup=True)
                # Acceptance of CancelCommand is not proof the remote process stopped.
                response = cli.call("ssm", "get-command-invocation", {"CommandId": command_id, "InstanceId": bastion.instance_id}, cleanup=True)
                if response.get("Status") in {"Success", "Failed", "TimedOut", "Cancelled"}:
                    state = response["Status"]
            except Exception:
                pass
            emit({"kind": "remote", "command_id": command_id, "instance_id": bastion.instance_id, "state": state})
