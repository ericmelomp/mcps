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
                assert {tool.name for tool in tools} == {"capabilities", "ec2_inventory", "ec2_health", "evidence_get"}
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
