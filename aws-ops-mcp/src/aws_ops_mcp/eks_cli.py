"""Bounded AWS CLI adapter. Only internal, fixed diagnostic operations are allowed."""

import json
import os
import shutil
import subprocess
import tempfile
import time


ALLOWED = {
    "sts": {"get-caller-identity", "assume-role"},
    "eks": {"list-clusters", "describe-cluster", "list-nodegroups", "describe-nodegroup",
            "list-addons", "describe-addon", "list-fargate-profiles", "describe-fargate-profile",
            "list-access-entries", "describe-access-entry", "list-associated-access-policies"},
    "ec2": {"describe-instances", "describe-instance-status", "describe-subnets", "describe-vpcs",
            "describe-security-groups", "describe-route-tables", "describe-network-acls", "describe-volumes"},
    "autoscaling": {"describe-auto-scaling-groups"},
    "elbv2": {"describe-load-balancers", "describe-target-groups", "describe-target-health",
              "describe-listeners", "describe-rules", "describe-load-balancer-attributes"},
    "cloudfront": {"list-distributions", "get-distribution"},
    "iam": {"get-role", "list-attached-role-policies", "list-role-policies"},
    "ssm": {"describe-instance-information", "send-command", "get-command-invocation", "cancel-command"},
}


class CollectionError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def safe_error(text):
    for marker, code in (("InvocationDoesNotExist", "invocation_pending"),
                         ("AccessDenied", "access_denied"), ("Unauthorized", "access_denied"),
                         ("ExpiredToken", "authentication_expired"), ("InvalidClientToken", "authentication_invalid"),
                         ("Throttl", "throttled"), ("ResourceNotFound", "resource_not_found")):
        if marker in text:
            return code
    return "aws_cli_failed"


class CLI:
    def __init__(self, account, region, stop=None, deadline=None):
        self.region, self.stop, self.deadline = region, stop, deadline or time.monotonic() + 1800
        self.binary = shutil.which("aws")
        if not self.binary:
            raise CollectionError("aws_cli_missing")
        self.env = dict(os.environ)
        # Do not inherit unrelated ambient credentials or endpoint overrides.
        for key in list(self.env):
            if key.startswith("AWS_ENDPOINT_URL") or key in {
                "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN",
                "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE",
            }:
                self.env.pop(key, None)
        self.env.update(AWS_PAGER="", AWS_CLI_AUTO_PROMPT="off", AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="true",
                        AWS_MAX_ATTEMPTS="2", AWS_RETRY_MODE="standard")
        if account.profile:
            self.env["AWS_PROFILE"] = account.profile
        if account.credentials_file:
            self.env["AWS_SHARED_CREDENTIALS_FILE"] = account.credentials_file
        if account.role_arn:
            credentials = self.call("sts", "assume-role", {
                "RoleArn": account.role_arn, "RoleSessionName": "aws-ops-eks", "DurationSeconds": 3600,
            })["Credentials"]
            self.env.pop("AWS_PROFILE", None)
            self.env.update(AWS_ACCESS_KEY_ID=credentials["AccessKeyId"],
                            AWS_SECRET_ACCESS_KEY=credentials["SecretAccessKey"],
                            AWS_SESSION_TOKEN=credentials["SessionToken"])
        self.identity = self.call("sts", "get-caller-identity")
        if self.identity.get("Account") != account.account_id:
            raise CollectionError("account_mismatch")

    def check(self):
        if self.stop and self.stop.is_set():
            raise CollectionError("cancelled")
        if time.monotonic() >= self.deadline:
            raise CollectionError("deadline_exceeded")

    def call(self, service, operation, parameters=None, cleanup=False):
        if operation not in ALLOWED.get(service, set()):
            raise CollectionError("operation_not_allowed")
        if not cleanup:
            self.check()
        args = [self.binary, service, operation, "--region", self.region, "--output", "json",
                "--no-cli-pager", "--no-paginate", "--cli-connect-timeout", "3", "--cli-read-timeout", "10"]
        if parameters:
            args.extend(["--cli-input-json", json.dumps(parameters)])
        timeout = 25 if cleanup else max(0.1, min(25, self.deadline - time.monotonic()))
        env = dict(self.env)
        if operation == "send-command":
            # SendCommand has no idempotency token; a transport retry could run twice.
            env["AWS_MAX_ATTEMPTS"] = "1"
        try:
            with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as error:
                process = subprocess.run(args, env=env, stdin=subprocess.DEVNULL, stdout=output, stderr=error,
                               timeout=timeout, check=False, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                output.seek(0)
                raw = output.read(8 * 1024 * 1024 + 1)
                error.seek(0)
                diagnostic = error.read(8192).decode("utf-8", errors="replace")
            if len(raw) > 8 * 1024 * 1024:
                raise CollectionError("aws_output_limit")
            if process.returncode:
                raise CollectionError(safe_error(diagnostic))
            # AWS CLI may emit warnings on stderr even on success.
            if not raw.strip():
                if diagnostic:
                    raise CollectionError(safe_error(diagnostic))
                return {}
            try:
                return json.loads(raw)
            except ValueError:
                raise CollectionError(safe_error(diagnostic)) from None
        except subprocess.TimeoutExpired:
            raise CollectionError("aws_cli_timeout") from None
        except OSError:
            raise CollectionError("aws_cli_unavailable") from None

    def pages(self, service, operation, key, parameters=None, token="nextToken", output_token=None):
        parameters, seen = dict(parameters or {}), set()
        for _ in range(100):
            page = self.call(service, operation, parameters)
            yield page.get(key, [])
            value = page.get(output_token or token)
            if not value:
                return
            if value in seen:
                raise CollectionError("pagination_cycle")
            seen.add(value)
            parameters[token] = value
        raise CollectionError("page_limit")
