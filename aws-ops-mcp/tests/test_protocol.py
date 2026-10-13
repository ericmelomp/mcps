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
                    "cloudfront_grpc_inspect", "elbv2_inspect", "waf_inspect", "waf_logs_search", "public_ip_lookup", "eks_network_dependency", "eks_rightsizing", "network_path_inspect", "network_flow_logs", "organization_summary", "cost_summary", "ops_investigate", "ops_investigation_get", "network_topology", "dns_diagnostics", "iam_policy_analyze", "iam_role_assessment", "compute_assessment", "database_assessment", "s3_assessment", "backup_assessment", "security_findings_summary", "incident_diagnostics", "terraform_plan_analysis", "cloudformation_health", "ecs_service_assessment", "serverless_assessment", "analytics_assessment", "ai_resource_assessment"}
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
                for name, arguments in (
                    ("eks_network_dependency", {"account":"test", "region":"us-east-1", "source_security_group_ids":["sg-00000000000000001"], "destination_kind":"opensearch", "destination_name":"demo"}),
                    ("eks_rightsizing", {"account":"test", "region":"us-east-1", "cluster":"demo", "namespace":"demo", "pod_name":"app"})):
                    assert next(t for t in tools if t.name == name).annotations.readOnlyHint is True
                    reply=await session.call_tool(name, arguments)
                    assert json.loads(reply.content[0].text)["errors"][0]["code"]=="configuration_invalid"
                for name, arguments in (
                    ("network_path_inspect", {"account":"test", "region":"us-east-1", "source_eni_id":"eni-00000000000000001", "destination_eni_id":"eni-00000000000000002", "port":443}),
                    ("network_flow_logs", {"account":"test", "region":"us-east-1", "log_group_name":"/vpc/flows", "start_time":"2026-01-01T00:00:00Z", "end_time":"2026-01-01T00:10:00Z", "interface_id":"eni-00000000000000001"})):
                    assert next(t for t in tools if t.name==name).annotations.readOnlyHint is True
                    response=await session.call_tool(name,arguments)
                    assert json.loads(response.content[0].text)["errors"][0]["code"]=="configuration_invalid"
                for name, arguments in (
                    ("organization_summary", {"account":"test", "region":"us-east-1"}),
                    ("cost_summary", {"account":"test", "region":"us-east-1", "start_date":"2026-01-01", "end_date":"2026-02-01"})):
                    assert next(t for t in tools if t.name==name).annotations.readOnlyHint is True
                    response=await session.call_tool(name,arguments)
                    assert json.loads(response.content[0].text)["errors"][0]["code"]=="configuration_invalid"
                for name, extra in (
                    ("network_topology", {}),
                    ("dns_diagnostics", {"hosted_zone_id":"ZDEMO","record_name":"www.example.test"}),
                    ("iam_role_assessment", {"role_name":"demo"})):
                    response=await session.call_tool(name,dict(account="test",region="us-east-1",**extra))
                    assert json.loads(response.content[0].text)["errors"][0]["code"]=="configuration_invalid"
                for name, extra in (
                    ("compute_assessment", {"instance_ids":["i-00000001"]}),
                    ("database_assessment", {"database_kind":"rds","resource_name":"demo"}),
                    ("s3_assessment", {"bucket_name":"demo-bucket"}),
                    ("backup_assessment", {"resource_arn":"arn:aws:ec2:us-east-1:000000000000:volume/vol-00000001"})):
                    response=await session.call_tool(name,dict(account="test",region="us-east-1",**extra))
                    assert json.loads(response.content[0].text)["errors"][0]["code"]=="configuration_invalid"
                for name, extra in (
                    ("security_findings_summary", {"services":["guardduty"]}),
                    ("incident_diagnostics", {"alarm_prefix":"demo", "include_cloudtrail":False}),
                    ("cloudformation_health", {"stack_name":"demo"}),
                    ("ecs_service_assessment", {"cluster_name":"demo","service_name":"app"}),
                    ("serverless_assessment", {"service_kind":"lambda","resource_name":"demo"}),
                    ("analytics_assessment", {"resource_name":"demo"}),
                    ("ai_resource_assessment", {"resource_kind":"knowledge_base","resource_name":"0123456789"})):
                    response=await session.call_tool(name,dict(account="test",region="us-east-1",**extra))
                    assert json.loads(response.content[0].text)["errors"][0]["code"]=="configuration_invalid"
                plan_result=await session.call_tool("terraform_plan_analysis", {"plan_json":json.dumps({"format_version":"1.2","resource_changes":[]})})
                assert json.loads(plan_result.content[0].text)["summary"]["apply_executed"] is False
                local_policy=await session.call_tool("iam_policy_analyze", {"policy_json":json.dumps({"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}})})
                assert json.loads(local_policy.content[0].text)["summary"]["effective_authorization_verified"] is False
                missing_ops=await session.call_tool("ops_investigation_get", {"investigation_id":"missing"})
                assert json.loads(missing_ops.content[0].text)["status"]=="error"
                bad_scope=await session.call_tool("ops_investigate", {"scopes":[], "analysis":"organization"})
                assert bad_scope.isError
                assert next(t for t in tools if t.name=='ops_investigate').annotations.readOnlyHint is True
                started=await session.call_tool('ops_investigate', {'scopes':[{'account':'test','region':'us-east-1'}], 'analysis':'organization'})
                job_id=json.loads(started.content[0].text)['investigation_id']
                for _ in range(50):
                    polled=await session.call_tool('ops_investigation_get', {'investigation_id':job_id})
                    progress=json.loads(polled.content[0].text)
                    if progress['summary']['state']=='finished':break
                    await asyncio.sleep(.01)
                assert progress['summary']['state']=='finished'
                assert progress['status']=='partial' and progress['items'][0]['errors'][0]['code']=='configuration_invalid'
                bad_port=await session.call_tool("network_path_inspect", {"account":"test", "region":"us-east-1", "source_eni_id":"eni-00000000000000001", "destination_eni_id":"eni-00000000000000002", "port":0})
                assert bad_port.isError
                invalid_hours=await session.call_tool("eks_rightsizing", {"account":"test", "region":"us-east-1", "cluster":"demo", "namespace":"demo", "pod_name":"app", "hours":9999})
                assert invalid_hours.isError
                assert next(t for t in tools if t.name == "eks_investigate").annotations.readOnlyHint is False
                schema = next(t for t in tools if t.name == "eks_investigate").inputSchema
                assert schema["properties"]["profile"]["default"] == "full"
                assert set(schema["properties"]["profile"]["enum"]) == {"full", "nodes", "workloads", "migration"}
                invalid_profile = await session.call_tool("eks_investigate", {"account":"test", "region":"us-east-1", "clusters":["demo"], "profile":"shell"})
                assert invalid_profile.isError
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
