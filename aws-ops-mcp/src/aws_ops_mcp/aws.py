"""Explicit AWS identity check and safe error codes."""

import boto3
import botocore.session
from botocore.config import Config
from botocore.exceptions import (
    ClientError, NoCredentialsError, PartialCredentialsError, ProfileNotFound,
    ConnectTimeoutError, ReadTimeoutError, EndpointConnectionError,
    CredentialRetrievalError, TokenRetrievalError,
)

from .config import Account


class AccountMismatch(Exception):
    pass


def error_code(exc: Exception) -> str:
    if isinstance(exc, AccountMismatch):
        return "account_mismatch"
    if isinstance(exc, (NoCredentialsError, PartialCredentialsError, ProfileNotFound,
                        CredentialRetrievalError, TokenRetrievalError)):
        return "authentication_unavailable"
    if isinstance(exc, (ConnectTimeoutError, ReadTimeoutError)):
        return "timeout"
    if isinstance(exc, EndpointConnectionError):
        return "endpoint_unavailable"
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code", "")
        if code in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}:
            return "access_denied"
        if code in {"ExpiredToken", "ExpiredTokenException", "RequestExpired", "InvalidClientTokenId", "AuthFailure"}:
            return "authentication_expired_or_invalid"
        if code in {"Throttling", "ThrottlingException", "RequestLimitExceeded"}:
            return "throttled"
        return "aws_api_error"
    return "internal_error"


def ec2_client(account: Account, region: str):
    options = Config(connect_timeout=3, read_timeout=5,
                     retries={"total_max_attempts": 2, "mode": "standard"},
                     ignore_configured_endpoint_urls=True)
    if account.credentials_file:
        source = botocore.session.Session()
        source.set_config_variable("credentials_file", account.credentials_file)
        session = boto3.Session(profile_name=account.profile, region_name=region, botocore_session=source)
    else:
        session = boto3.Session(profile_name=account.profile, region_name=region)
    if account.role_arn:
        credentials = session.client("sts", config=options).assume_role(
            RoleArn=account.role_arn, RoleSessionName="aws-ops-mcp", DurationSeconds=900
        )["Credentials"]
        session = boto3.Session(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"], region_name=region,
        )
    actual = session.client("sts", config=options).get_caller_identity()["Account"]
    if actual != account.account_id:
        raise AccountMismatch()
    return session.client("ec2", config=options)
