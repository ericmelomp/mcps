"""Local account aliases. Credentials are never stored here."""

import json
import os
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Account(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    account_id: str = Field(pattern=r"^\d{12}$")
    regions: list[str] = Field(min_length=1, max_length=50)
    profile: str | None = Field(default=None, min_length=1, max_length=128)
    credentials_file: str | None = Field(default=None, min_length=1, max_length=4096)
    role_arn: str | None = Field(default=None, pattern=r"^arn:aws(?:-us-gov|-cn)?:iam::\d{12}:role/[\w+=,.@/-]+$", max_length=2048)

    @field_validator("regions")
    @classmethod
    def validate_regions(cls, values):
        import re
        if any(not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d+", value) for value in values):
            raise ValueError("Invalid region")
        return values


class ConfigurationError(Exception):
    pass


def resolve(account: str, region: str) -> Account:
    path = os.environ.get("AWS_OPS_CONFIG")
    if not path:
        raise ConfigurationError("Set AWS_OPS_CONFIG to an account configuration file")
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
        if set(data) != {"accounts"} or not isinstance(data["accounts"], dict):
            raise ValueError()
        entry = Account.model_validate(data["accounts"][account])
        if region not in entry.regions:
            raise ValueError()
        if entry.role_arn and entry.role_arn.split(":")[4] != entry.account_id:
            raise ValueError()
        return entry
    except (OSError, ValueError, KeyError, TypeError):
        raise ConfigurationError("Invalid configuration, unknown alias or region not allowed") from None
