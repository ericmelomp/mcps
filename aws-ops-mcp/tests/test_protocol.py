import asyncio
import json
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def test_real_stdio_discovery_validation_and_safe_calls():
    async def exercise():
        params = StdioServerParameters(command=sys.executable, args=["-m", "aws_ops_mcp.server"],
                                       env={"AWS_EC2_METADATA_DISABLED": "true", "AWS_OPS_CONFIG": ""})
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = (await session.list_tools()).tools
                assert {tool.name for tool in tools} == {"capabilities", "ec2_inventory", "ec2_health", "evidence_get",
                    "eks_inventory", "eks_investigate", "eks_investigation_get", "eks_investigation_cancel", "eks_logs",
                    "cloudfront_grpc_inspect", "elbv2_inspect", "waf_inspect", "waf_logs_search", "public_ip_lookup"}
                for name in ("cloudfront_grpc_inspect", "elbv2_inspect"):
                    assert next(t for t in tools if t.name == name).annotations.readOnlyHint is True
                    absent = await session.call_tool(name, {"account": "test", "region": "us-east-1"})
                    assert json.loads(absent.content[0].text)["errors"][0]["code"] == "configuration_invalid"
                for name, extra in (
                    ("waf_inspect", {"web_acl_arn": "arn:aws:wafv2:us-east-1:000000000000:global/webacl/demo/abc"}),
                    ("waf_logs_search", {"web_acl_arn": "arn:aws:wafv2:us-east-1:000000000000:global/webacl/demo/abc", "start_time": "2026-01-01T00:00:00Z", "end_time": "2026-01-01T00:01:00Z", "request_ids": ["req"]}),
                    ("public_ip_lookup", {"public_ip": "8.8.8.8"})):
                    assert next(t for t in tools if t.name == name).annotations.readOnlyHint is True
                    response = await session.call_tool(name, dict(account="test", region="us-east-1", **extra))
                    assert json.loads(response.content[0].text)["errors"][0]["code"] == "configuration_invalid"
                assert next(t for t in tools if t.name == "eks_investigate").annotations.readOnlyHint is False
                eks = await session.call_tool("eks_investigate", {"account": "test", "region": "us-east-1", "clusters": ["demo"]})
                assert json.loads(eks.content[0].text)["errors"][0]["code"] == "configuration_invalid"
                invalid_eks = await session.call_tool("eks_investigate", {"account": "test", "region": "us-east-1", "clusters": ["demo; touch /tmp/unsafe"]})
                assert invalid_eks.isError
                result = await session.call_tool("capabilities", {})
                assert not result.isError
                assert result.structuredContent is None
                assert len(result.content) == 1
                assert json.loads(result.content[0].text)["status"] == "ok"
                missing = await session.call_tool("ec2_inventory", {"account": "test", "region": "us-east-1"})
                assert json.loads(missing.content[0].text)["errors"][0]["code"] == "configuration_invalid"
                expired = await session.call_tool("evidence_get", {"evidence_id": "missing"})
                assert json.loads(expired.content[0].text)["status"] == "error"
                invalid = await session.call_tool("evidence_get", {"evidence_id": "missing", "limit": 500})
                assert invalid.isError
                unsupported = await session.call_tool("rds_health", {})
                assert unsupported.isError
    asyncio.run(exercise())
