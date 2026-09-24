from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from aws_ops_mcp.aws import AccountMismatch, ec2_client, error_code
from aws_ops_mcp.config import Account, ConfigurationError, resolve


def test_configuration_requires_allowed_region(configured):
    assert resolve("test", "us-east-1").account_id == "000000000000"
    with pytest.raises(ConfigurationError):
        resolve("test", "eu-west-1")
    with pytest.raises(ConfigurationError):
        resolve("other", "us-east-1")


def test_account_mismatch_prevents_ec2_client():
    session = MagicMock()
    session.client.return_value.get_caller_identity.return_value = {"Account": "999999999999"}
    with patch("aws_ops_mcp.aws.boto3.Session", return_value=session):
        with pytest.raises(AccountMismatch):
            ec2_client(Account(account_id="000000000000", regions=["us-east-1"]), "us-east-1")
    assert [call.args[0] for call in session.client.call_args_list] == ["sts"]


def test_assumed_session_is_the_one_verified():
    source, target = MagicMock(), MagicMock()
    source.client.return_value.assume_role.return_value = {"Credentials": {
        "AccessKeyId": "example", "SecretAccessKey": "example", "SessionToken": "example"
    }}
    target.client.return_value.get_caller_identity.return_value = {"Account": "000000000000"}
    account = Account(account_id="000000000000", regions=["us-east-1"],
                      role_arn="arn:aws:iam::000000000000:role/read", profile="source")
    with patch("aws_ops_mcp.aws.boto3.Session", side_effect=[source, target]):
        ec2_client(account, "us-east-1")
    source.client.return_value.get_caller_identity.assert_not_called()
    target.client.return_value.get_caller_identity.assert_called_once()


@pytest.mark.parametrize("code,expected", [("AccessDenied", "access_denied"),
    ("ExpiredToken", "authentication_expired_or_invalid"), ("Throttling", "throttled")])
def test_errors_do_not_expose_aws_message(code, expected):
    exc = ClientError({"Error": {"Code": code, "Message": "sensitive payload"}}, "Example")
    assert error_code(exc) == expected
