from copy import deepcopy
from unittest.mock import MagicMock

import pytest

from aws_ops_mcp.edge import Edge, wildcard
from aws_ops_mcp.evidence import EvidenceStore
from aws_ops_mcp.eks_cli import ALLOWED, CollectionError


def distribution():
    return {"Distribution": {"Status": "Deployed", "DistributionConfig": {
        "Enabled": True, "HttpVersion": "http2", "WebACLId": "example-acl",
        "Origins": {"Items": [{"Id": "origin", "DomainName": "example.elb.amazonaws.com",
            "CustomHeaders": {"Items": [{"HeaderName": "secret", "HeaderValue": "DO-NOT-EXPOSE"}]},
            "CustomOriginConfig": {"OriginProtocolPolicy": "https-only", "HTTPSPort": 443}}]},
        "DefaultCacheBehavior": {"TargetOriginId": "origin", "GrpcConfig": {"Enabled": True},
            "AllowedMethods": {"Items": ["GET", "HEAD", "POST"]}, "ViewerProtocolPolicy": "https-only"}}}}


def service(cli):
    return Edge(EvidenceStore(), factory=lambda *args, **kwargs: cli)


def cf(cli, **kwargs):
    return service(cli).query("test", "us-east-1", "cloudfront", distribution_id="E123", **kwargs)


def test_grpc_requirements_and_evidence_redaction(configured):
    cli = MagicMock()
    cli.call.return_value = distribution()
    result = cf(cli)
    assert result["status"] == "ok"
    assert result["summary"]["assessed_behaviors"] == 1
    assert "DO-NOT-EXPOSE" not in str(result)
    assert "evidence_id" in result
    assert "not end-to-end" in result["coverage"]["scope"]


@pytest.mark.parametrize("version,expected", [("http1.1", "degraded"), ("http3", "degraded"),
    ("http2", "ok"), ("http2and3", "ok")])
def test_http_versions(configured, version, expected):
    cli = MagicMock()
    data = distribution()
    data["Distribution"]["DistributionConfig"]["HttpVersion"] = version
    cli.call.return_value = data
    assert cf(cli)["status"] == expected


def test_blocks_and_ordered_behavior_selection(configured):
    cli = MagicMock()
    data = distribution()
    config = data["Distribution"]["DistributionConfig"]
    default = config["DefaultCacheBehavior"]
    specific = deepcopy(default)
    specific["PathPattern"] = "/package.Service/*"
    broad = deepcopy(default)
    broad.update(PathPattern="/package.*", GrpcConfig={"Enabled": False})
    config["CacheBehaviors"] = {"Items": [specific, broad]}
    default.pop("GrpcConfig")
    default["AllowedMethods"]["Items"] = ["GET", "HEAD"]
    cli.call.return_value = data
    assert cf(cli, path="/package.Service/Method")["status"] == "ok"
    other = cf(cli, path="/other.Service/Method")
    assert {f["code"] for f in other["findings"]} == {"grpc_disabled", "post_not_allowed"}
    config["Origins"]["Items"][0]["CustomOriginConfig"]["OriginProtocolPolicy"] = "http-only"
    assert "origin_https_required" in {f["code"] for f in cf(cli)["findings"]}


@pytest.mark.parametrize("path", ["/x/../y", "/x%2fy", "x/y", "/x?query=1", "/x//y"])
def test_ambiguous_path_rejected(configured, path):
    cli = MagicMock()
    assert cf(cli, path=path)["errors"][0]["code"] == "path_requires_canonical_literal"
    cli.call.assert_not_called()


def test_wildcard_does_not_use_shell_character_classes():
    assert wildcard("/pkg.*/?", "/pkg.Service/M")
    assert not wildcard("/[ab]", "/a")
    assert wildcard("/[ab]", "/[ab]")


def test_paginated_discovery_and_alias(configured):
    cli = MagicMock()
    cli.call.side_effect = [
        {"DistributionList": {"Items": [], "IsTruncated": True, "NextMarker": "next"}},
        {"DistributionList": {"Items": [{"Id": "E123", "DomainName": "d123.cloudfront.net",
            "Aliases": {"Items": ["*.example.test"]}}], "IsTruncated": False}}, distribution()]
    result = service(cli).query("test", "us-east-1", "cloudfront", hostname="rpc.example.test")
    assert result["status"] == "ok"
    assert cli.call.call_args_list[1].args[2]["Marker"] == "next"
    assert result["summary"]["distribution_id"] == "E123"


def test_denied_details_preserve_discovery(configured):
    cli = MagicMock()
    cli.call.side_effect = [{"DistributionList": {"Items": [{"Id": "E123", "DomainName": "d.cloudfront.net"}]}},
                            CollectionError("access_denied")]
    result = service(cli).query("test", "us-east-1", "cloudfront", hostname="d.cloudfront.net")
    assert result["status"] == "partial"
    assert not result["coverage"]["complete"]
    assert result["items"][0]["id"] == "E123"


def test_unsupported_origin_is_not_healthy(configured):
    cli = MagicMock()
    data = distribution()
    data["Distribution"]["DistributionConfig"]["Origins"]["Items"][0].pop("CustomOriginConfig")
    cli.call.return_value = data
    assert cf(cli)["status"] == "partial"


def elb_cli(protocol="GRPC", lb_type="application", deny_health=False):
    cli = MagicMock()
    def pages(service, operation, key, parameters, **kwargs):
        return iter([{
            "describe-load-balancers": [{"LoadBalancerArn": "arn", "DNSName": "example.elb.amazonaws.com",
                "Type": lb_type, "State": {"Code": "active"}}],
            "describe-listeners": [{"ListenerArn": "listener", "Protocol": "HTTPS", "Port": 443,
                "DefaultActions": [{"Type": "authenticate-oidc", "AuthenticateOidcConfig": {"ClientSecret": "SECRET"}},
                    {"Type": "forward", "TargetGroupArn": "tg"}]}],
            "describe-rules": [{"RuleArn": "rule", "Priority": "1", "Conditions": [
                {"Field": "http-header", "HttpHeaderConfig": {"Values": ["SECRET"]}},
                {"Field": "host-header", "Values": ["rpc.example.test"]}], "Actions": []}],
            "describe-target-groups": [{"TargetGroupArn": "tg", "ProtocolVersion": protocol}],
        }[operation]])
    def call(service, operation, params):
        if operation == "describe-load-balancer-attributes":
            return {"Attributes": [{"Key": "routing.http2.enabled", "Value": "true"}]}
        if deny_health:
            raise CollectionError("access_denied")
        return {"TargetHealthDescriptions": [{"Target": {"Id": "example", "Port": 443}, "TargetHealth": {"State": "healthy"}}]}
    cli.pages.side_effect, cli.call.side_effect = pages, call
    return cli


def test_alb_health_and_redaction(configured):
    result = service(elb_cli()).query("test", "us-east-1", "elbv2", load_balancer_arn="arn")
    assert result["status"] == "ok"
    assert "SECRET" not in str(result)
    assert any(x["kind"] == "rule" for x in result["items"])


def test_elb_partial_and_protocol_mismatch(configured):
    result = service(elb_cli(protocol="HTTP1", deny_health=True)).query("test", "us-east-1", "elbv2", load_balancer_arn="arn")
    assert result["status"] == "partial"
    assert result["errors"][0]["code"] == "access_denied"
    assert result["findings"][0]["code"] == "target_group_http1_not_grpc_compatible"


def test_nlb_does_not_require_grpc_target_protocol(configured):
    cli = elb_cli(protocol=None, lb_type="network")
    result = service(cli).query("test", "us-east-1", "elbv2", dns_name="example.elb.amazonaws.com")
    assert result["status"] == "ok"
    assert all(c.args[1] != "describe-rules" for c in cli.pages.call_args_list)


def test_identity_failure_and_deadline_are_explicit(configured):
    for code in ("account_mismatch", "deadline_exceeded", "authentication_expired"):
        def factory(*args, **kwargs):
            assert 0 < kwargs["deadline"]
            raise CollectionError(code)
        result = Edge(EvidenceStore(), factory).query("test", "us-east-1", "cloudfront")
        assert result["status"] == "error"
        assert result["errors"] == [{"code": code}]


def test_edge_allowlist_contains_no_mutation():
    assert all(x.startswith(("get-", "list-")) for x in ALLOWED["cloudfront"])
    assert all(x.startswith("describe-") for x in ALLOWED["elbv2"])
