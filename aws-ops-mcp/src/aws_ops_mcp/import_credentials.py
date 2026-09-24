"""Agent-side onboarding: JSON on stdin, named temporary profiles on disk.

Never put credentials in command-line arguments or print input/errors verbatim.
This helper is intentionally not an MCP tool: the agent prepares access once,
then invokes the existing small read-only tools.
"""

import argparse
import configparser
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile

import boto3
from botocore.config import Config
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError

from .aws import error_code
from .config import Account


class TemporaryAccount(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    alias: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")
    regions: list[str] = Field(min_length=1, max_length=50)
    aws_access_key_id: SecretStr
    aws_secret_access_key: SecretStr
    aws_session_token: SecretStr
    account_id: str | None = Field(default=None, pattern=r"^\d{12}$")


class ImportFailure(Exception):
    def __init__(self, code, alias=None):
        self.code, self.alias = code, alias
        super().__init__(code)


def verify_identity(entry):
    session = boto3.Session(
        aws_access_key_id=entry.aws_access_key_id.get_secret_value(),
        aws_secret_access_key=entry.aws_secret_access_key.get_secret_value(),
        aws_session_token=entry.aws_session_token.get_secret_value(),
        region_name=entry.regions[0],
    )
    client = session.client("sts", config=Config(
        connect_timeout=3, read_timeout=5,
        retries={"total_max_attempts": 2, "mode": "standard"},
        ignore_configured_endpoint_urls=True,
    ))
    try:
        return client.get_caller_identity()["Account"]
    finally:
        client.close()


def atomic_write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".aws-ops-", dir=path.parent)
    try:
        # mkstemp uses user-only permissions on POSIX; Windows inherits directory ACLs.
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _import_batch(payload, config_path, credentials_path, verify):
    config_path, credentials_path = Path(config_path).resolve(), Path(credentials_path).resolve()
    if config_path == credentials_path:
        raise ImportFailure("invalid_paths")
    try:
        if not isinstance(payload, dict) or set(payload) != {"accounts"}:
            raise ValueError()
        if not isinstance(payload["accounts"], list) or not 1 <= len(payload["accounts"]) <= 50:
            raise ValueError()
        entries = [TemporaryAccount.model_validate(item) for item in payload["accounts"]]
        if len({entry.alias for entry in entries}) != len(entries):
            raise ValueError()
        for entry in entries:
            Account(account_id="000000000000", regions=entry.regions)
            for field in (entry.aws_access_key_id, entry.aws_secret_access_key, entry.aws_session_token):
                value = field.get_secret_value()
                if not value or len(value) > 32768 or any(character.isspace() for character in value):
                    raise ValueError()
        config = json.loads(config_path.read_text(encoding="utf-8-sig")) if config_path.exists() else {"accounts": {}}
        if set(config) != {"accounts"} or not isinstance(config["accounts"], dict):
            raise ValueError()
        if config["accounts"] == {"minha-conta": {
            "account_id": "000000000000", "profile": "SUBSTITUA_PELO_SEU_PROFILE", "regions": ["us-east-1"]
        }}:
            config["accounts"] = {}
        profiles = configparser.RawConfigParser()
        if credentials_path.exists():
            profiles.read_string(credentials_path.read_text(encoding="utf-8-sig"))
    except (ValueError, TypeError, KeyError, OSError, configparser.Error):
        raise ImportFailure("invalid_input_or_local_configuration") from None

    # Validate the whole batch before changing files. A bad alias never silently
    # switches an established account to a different AWS account.
    registrations = []
    for entry in entries:
        try:
            account_id = verify(entry)
        except Exception as exc:
            raise ImportFailure(error_code(exc), entry.alias) from None
        existing = config["accounts"].get(entry.alias)
        expected = existing.get("account_id") if isinstance(existing, dict) else None
        if (entry.account_id and entry.account_id != account_id) or (expected and expected != account_id):
            raise ImportFailure("account_mismatch", entry.alias)
        try:
            profile_key = f"{config_path}|{entry.alias}|{account_id}"
            profile = "aws-ops-" + hashlib.sha256(profile_key.encode()).hexdigest()[:20]
            validated = Account(account_id=account_id, regions=entry.regions, profile=profile,
                                credentials_file=str(credentials_path))
        except ValidationError:
            raise ImportFailure("invalid_identity", entry.alias) from None
        profiles[profile] = {
            "aws_access_key_id": entry.aws_access_key_id.get_secret_value(),
            "aws_secret_access_key": entry.aws_secret_access_key.get_secret_value(),
            "aws_session_token": entry.aws_session_token.get_secret_value(),
        }
        config["accounts"][entry.alias] = validated.model_dump(exclude_none=True)
        registrations.append({"alias": entry.alias, "account_id": account_id, "regions": entry.regions})

    output = io.StringIO()
    profiles.write(output)
    try:
        atomic_write(credentials_path, output.getvalue())
        atomic_write(config_path, json.dumps(config, indent=2) + "\n")
    except OSError:
        # The credentials file can already have been updated; safe to retry.
        raise ImportFailure("local_write_failed_retry_import") from None
    return {"status": "ok", "registered": registrations, "credential_values_returned": False}


def import_batch(payload, config_path, credentials_path, verify=verify_identity):
    credentials_path = Path(credentials_path).resolve()
    lock = credentials_path.with_name("credentials.import.lock")
    try:
        lock.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        raise ImportFailure("import_in_progress") from None
    except OSError:
        raise ImportFailure("local_storage_unavailable") from None
    try:
        os.close(descriptor)
        return _import_batch(payload, config_path, credentials_path, verify)
    finally:
        lock.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description="Import named temporary AWS credentials from JSON stdin")
    parser.add_argument("--config", default=os.environ.get("AWS_OPS_CONFIG"))
    args = parser.parse_args()
    if not args.config:
        print(json.dumps({"status": "error", "code": "configuration_path_required"}))
        return 1
    try:
        text = sys.stdin.read(2 * 1024 * 1024 + 1)
        if len(text) > 2 * 1024 * 1024:
            raise ImportFailure("input_too_large")
        payload = json.loads(text)
        result = import_batch(payload, args.config, Path.home() / ".aws" / "aws-ops-mcp" / "credentials")
    except ImportFailure as exc:
        print(json.dumps({"status": "error", "code": exc.code, "alias": exc.alias}))
        return 1
    except Exception:
        print(json.dumps({"status": "error", "code": "import_failed"}))
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
