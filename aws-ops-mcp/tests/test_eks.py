import json
import os
import threading
import time
from unittest.mock import MagicMock

import pytest

from aws_ops_mcp.config import Account
from aws_ops_mcp.contracts import encoded
from aws_ops_mcp.evidence import EvidenceStore
from aws_ops_mcp.eks_cli import CLI, CollectionError
from aws_ops_mcp.eks_collect import Collector
from aws_ops_mcp.eks_jobs import Investigations
from aws_ops_mcp.eks_kubernetes import PATHS, analyze, correlate, normalize
from aws_ops_mcp.eks_ssm import Bastion, decode_result, recipe, resolve_bastion, run_recipe
from aws_ops_mcp import eks_remote


ACCOUNT = Account(account_id="000000000000", regions=["us-east-1"], profile="diagnostic")
BASTION = Bastion(account="test", region="us-east-1", cluster="demo", instance_id="i-00000000000000001")
PAYLOAD = {"account_id": "000000000000", "region": "us-east-1", "cluster": "demo",
           "cluster_arn": "arn:aws:eks:us-east-1:000000000000:cluster/demo", "kind": "pods"}


def pod(phase="Running", reason=None):
    return {"metadata": {"name": "app", "namespace": "default", "annotations": {"secret": "NEVER_RETURN"}},
            "spec": {"containers": [{"name": "app", "env": [{"name": "PASSWORD", "value": "NEVER_RETURN"}]}]},
            "status": {"phase": phase, "conditions": [{"type": "Ready", "status": "False"}],
                       "containerStatuses": [{"name": "app", "ready": False, "state": {"waiting": {"reason": reason}}}]}}


def test_cli_profile_isolation_identity_and_no_shell(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "UNRELATED")
    monkeypatch.setenv("AWS_ENDPOINT_URL_EKS", "https://invalid")
    monkeypatch.setattr("shutil.which", lambda _: "aws")
    calls = []
    def run(args, **kwargs):
        calls.append((args, kwargs))
        kwargs["stdout"].write(json.dumps({"Account": "000000000000", "Arn": "example"}).encode())
        return type("Result", (), {"returncode": 0})()
    monkeypatch.setattr("subprocess.run", run)
    cli = CLI(ACCOUNT, "us-east-1")
    assert "AWS_ACCESS_KEY_ID" not in calls[0][1]["env"]
    assert "AWS_ENDPOINT_URL_EKS" not in calls[0][1]["env"]
    assert calls[0][1]["env"]["AWS_PROFILE"] == "diagnostic"
    assert calls[0][1].get("shell") is None
    with pytest.raises(CollectionError, match="operation_not_allowed"):
        cli.call("eks", "delete-cluster")


def test_cli_account_mismatch(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: "aws")
    monkeypatch.setattr(CLI, "call", lambda *a, **k: {"Account": "999999999999"})
    with pytest.raises(CollectionError, match="account_mismatch"):
        CLI(ACCOUNT, "us-east-1")


def test_cli_sanitizes_errors(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: "aws")
    def run(args, **kwargs):
        kwargs["stderr"].write(b"AccessDenied sensitive secret content")
        return type("Result", (), {"returncode": 254})()
    monkeypatch.setattr("subprocess.run", run)
    with pytest.raises(CollectionError) as error:
        CLI(ACCOUNT, "us-east-1")
    assert str(error.value) == "access_denied"


def test_cli_pagination_and_cycle():
    cli = object.__new__(CLI)
    cli.call = MagicMock(side_effect=[{"clusters": ["one"], "nextToken": "x"}, {"clusters": ["two"]}])
    assert list(cli.pages("eks", "list-clusters", "clusters")) == [["one"], ["two"]]
    cli.call = MagicMock(return_value={"clusters": [], "nextToken": "x"})
    with pytest.raises(CollectionError, match="pagination_cycle"):
        list(cli.pages("eks", "list-clusters", "clusters"))


def test_bastion_mapping_requires_unique_exact_target(monkeypatch, tmp_path):
    path = tmp_path / "bastions.json"
    monkeypatch.setenv("AWS_OPS_EKS_CONFIG", str(path))
    path.write_text(json.dumps({"bastions": [BASTION.model_dump()]}))
    assert resolve_bastion("test", "us-east-1", "demo") == BASTION
    with pytest.raises(CollectionError):
        resolve_bastion("other", "us-east-1", "demo")
    path.write_text(json.dumps({"bastions": [BASTION.model_dump(), BASTION.model_dump()]}))
    with pytest.raises(CollectionError):
        resolve_bastion("test", "us-east-1", "demo")


def test_pods_normalized_without_env_annotations_or_messages():
    item = normalize("pods", pod(reason="CrashLoopBackOff"))
    assert "NEVER_RETURN" not in json.dumps(item)
    assert any(f["code"] == "CrashLoopBackOff" for f in analyze(item))
    assert analyze(normalize("pods", pod(phase="Succeeded"))) == []


@pytest.mark.parametrize("kind,obj,code", [
    ("nodes", {"status": {"conditions": [{"type": "Ready", "status": "Unknown"}]}}, "node_not_ready"),
    ("deployments", {"spec": {"replicas": 3}, "status": {"readyReplicas": 1}}, "workload_replicas_unavailable"),
    ("persistentvolumeclaims", {"status": {"phase": "Pending"}}, "pvc_not_bound"),
    ("jobs", {"status": {"conditions": [{"type": "Failed", "status": "True"}]}}, "job_failed"),
    ("horizontalpodautoscalers", {"status": {"conditions": [{"type": "ScalingActive", "status": "False"}]}}, "hpa_unavailable"),
])
def test_kubernetes_checks(kind, obj, code):
    assert any(f["code"] == code for f in analyze(normalize(kind, obj)))


def test_no_endpoint_absence_claim_from_incomplete_collection():
    service = normalize("services", {"metadata": {"name": "app", "namespace": "default"}, "spec": {"selector": {"app": "app"}}})
    assert correlate([service], {"services"}) == []
    assert correlate([service], {"services", "endpointslices"})[0]["code"] == "service_without_ready_endpoints"


def test_null_endpointslice_is_an_empty_collection_not_a_collection_failure():
    item = normalize('endpointslices', {'metadata':{'name':'empty'}, 'endpoints':None})
    assert item['endpoints'] == 0
    assert item['ready'] == 0
    assert normalize('endpointslices', {'endpoints':[{'conditions':None}]})['ready'] == 1


def remote_harness(monkeypatch, pages, account="000000000000"):
    calls, paths = [], []
    monkeypatch.setattr(eks_remote, "PATHS", PATHS, raising=False)
    monkeypatch.setattr(eks_remote, "normalize", normalize, raising=False)
    monkeypatch.setattr(eks_remote, "analyze", analyze, raising=False)
    def execute(args, env, text=False):
        calls.append(args)
        if "get-caller-identity" in args:
            return {"Account": account, "Arn": "arn:aws:sts::000000000000:assumed-role/bastion/session"}
        if "describe-cluster" in args:
            return {"cluster": {"arn": PAYLOAD["cluster_arn"], "endpoint": "https://example.invalid",
                                "certificateAuthority": {"data": "EXAMPLE"}}}
        path = args[args.index("--kubeconfig") + 1]
        paths.append(path)
        config = json.loads(open(path, encoding="utf-8").read())
        assert config["current-context"] == "diagnostic"
        assert "insecure-skip-tls-verify" not in json.dumps(config)
        value = pages.pop(0)
        if isinstance(value, Exception):
            raise value
        return value
    monkeypatch.setattr(eks_remote, "execute", execute)
    return calls, paths


def test_remote_pagination_preserves_partial_and_cleans_kubeconfig(monkeypatch):
    calls, paths = remote_harness(monkeypatch, [{"items": [pod(reason="CrashLoopBackOff")], "metadata": {"continue": "cursor/="}}, RuntimeError("kubernetes_forbidden")])
    result = eks_remote.remote_collect(PAYLOAD)
    assert result["complete"] is False
    assert result["observed"] == 1
    assert result["findings"]
    assert "cursor%2F%3D" in calls[-1][-1]
    assert all(not os.path.exists(path) for path in paths)


def test_remote_single_page_returns_snapshot_cursor(monkeypatch):
    calls, _ = remote_harness(monkeypatch, [{'items':[pod()], 'metadata':{'continue':'next','resourceVersion':'123'}}])
    result = eks_remote.remote_collect({**PAYLOAD, 'paged':True, 'page_size':50, 'resource_version':'123'})
    assert result['next_token'] == 'next'
    assert result['resource_version'] == '123'
    assert 'resourceVersionMatch=Exact' in calls[-1][-1]
    assert 'limit=50' in calls[-1][-1]


def test_ssm_page_reduction_does_not_discard_or_double_count(monkeypatch):
    from aws_ops_mcp import eks_collect
    calls=[]
    def remote(cli, bastion, payload, emit):
        calls.append(payload)
        if len(calls)==1:
            return {'complete':True,'items':[{'name':'discarded-sample'}], 'observed':100,
                    'output_truncated':True,'resource_version':'123','next_token':'wrong-cursor'}
        if len(calls)==2:
            return {'complete':True,'items':[{'name':'first'}], 'observed':1,
                    'resource_version':'123','next_token':'correct-cursor'}
        return {'complete':True,'items':[{'name':'second'}], 'observed':1,'resource_version':'123'}
    monkeypatch.setattr(eks_collect,'run_recipe',remote)
    collector=Collector(FakeCLI(ACCOUNT,'us-east-1',threading.Event()),'test','demo',lambda e:None)
    result=collector.remote_pages(BASTION,{'kind':'pods'})
    assert result['complete'] is True
    assert result['observed']==2
    assert [i['name'] for i in result['items']]==['first','second']
    assert calls[1]['page_size']==50 and calls[1]['page_token']=='' and calls[1]['resource_version']=='123'
    assert calls[2]['page_token']=='correct-cursor'


@pytest.mark.parametrize('failure', ['denied','snapshot'])
def test_ssm_pages_preserve_prior_results_on_failure(monkeypatch,failure):
    from aws_ops_mcp import eks_collect
    calls=[]
    def remote(*args):
        calls.append(args)
        if len(calls)==1:
            return {'complete':True,'items':[{'name':'first'}], 'observed':1,'resource_version':'123','next_token':'next'}
        if failure=='denied':
            raise CollectionError('access_denied')
        return {'complete':True,'items':[{'name':'mixed-snapshot'}],'observed':1,'resource_version':'999'}
    monkeypatch.setattr(eks_collect,'run_recipe',remote)
    collector=Collector(FakeCLI(ACCOUNT,'us-east-1',threading.Event()),'test','demo',lambda e:None)
    result=collector.remote_pages(BASTION,{'kind':'pods'})
    assert result['complete'] is False
    assert result['items']==[{'name':'first'}]


def test_remote_account_mismatch_stops_before_cluster(monkeypatch):
    calls, _ = remote_harness(monkeypatch, [], account="999999999999")
    with pytest.raises(RuntimeError, match="remote_account_mismatch"):
        eks_remote.remote_collect(PAYLOAD)
    assert len(calls) == 1


def test_remote_bounds_stdout_but_retains_counts(monkeypatch):
    remote_harness(monkeypatch, [{"items": [pod(reason="CrashLoopBackOff") for _ in range(300)]}])
    result = eks_remote.remote_collect(PAYLOAD)
    wire = eks_remote.pack_result(result)
    assert len(wire) <= 18000
    decoded = decode_result(wire)
    assert result["complete"] is True
    assert result["observed"] == 300
    assert result["output_truncated"] is False
    assert len(decoded["items"]) == 300


def test_compressed_ssm_rejects_bombs_and_trailing_streams():
    import base64, zlib
    for payload in (zlib.compress(b'x' * (4 * 1024 * 1024 + 1)), zlib.compress(b'{}') + b'trailing'):
        wire = json.dumps({'encoding':'zlib-base64-v1','payload':base64.b64encode(payload).decode()})
        with pytest.raises(ValueError):
            decode_result(wire)


def test_remote_logs_bounded_and_redacted(monkeypatch):
    calls, _ = remote_harness(monkeypatch, ['password=hunter2 token=abc ASIA1234567890123456 Authorization: Bearer privateValue "password":"privateJson" AWS_SECRET_ACCESS_KEY=privateKey'])
    result = eks_remote.remote_collect({**PAYLOAD, "kind": "logs", "log_target": {"pod": "app", "namespace": "default", "container": "app"}})
    assert "hunter2" not in result["items"][0]["text"]
    assert "private" not in result["items"][0]["text"]
    assert "--limit-bytes=10000" in calls[-1]
    assert "--since=10m" in calls[-1]


def test_recipe_is_valid_python_with_literal_payload():
    command = recipe({**PAYLOAD, "cluster": "demo'; malicious() #"})
    source = command.split("\n", 1)[1].rsplit("\n", 1)[0]
    compile(source, "recipe", "exec")
    assert command.startswith("python3 - <<'AWS_OPS_EKS_RECIPE'")


def ssm_cli(responses):
    cli = MagicMock()
    cli.deadline = time.monotonic() + 300
    cli.call.side_effect = responses
    cli.stop = threading.Event()
    return cli


COMMAND = {"Command": {"CommandId": "00000000-0000-0000-0000-000000000000"}}


def test_ssm_success_and_payload_shape():
    cli = ssm_cli([COMMAND, {"Status": "Success", "ResponseCode": 0, "StandardOutputContent": json.dumps({"items": [], "complete": True})}])
    events = []
    assert run_recipe(cli, BASTION, PAYLOAD, events.append)["complete"]
    assert events[-1]["state"] == "Success"
    import botocore.session
    from botocore.validate import validate_parameters
    model = botocore.session.get_session().get_service_model("ssm")
    validate_parameters(cli.call.call_args_list[0].args[2], model.operation_model("SendCommand").input_shape)


def test_ssm_cancellation_is_not_falsely_confirmed():
    cli = ssm_cli([COMMAND, CollectionError("cancelled"), {}, {"Status": "Cancelling"}])
    events = []
    with pytest.raises(CollectionError):
        run_recipe(cli, BASTION, PAYLOAD, events.append)
    assert events[-1]["state"] == "cancellation_unconfirmed"
    assert cli.call.call_args_list[-2].args[1] == "cancel-command"


def test_ssm_submission_timeout_is_ambiguous():
    cli = ssm_cli([CollectionError("aws_cli_timeout")])
    events = []
    with pytest.raises(CollectionError, match="ssm_submission_unconfirmed"):
        run_recipe(cli, BASTION, PAYLOAD, events.append)
    assert events[-1]["state"] == "submission_unconfirmed"


def test_ssm_truncated_output_never_healthy():
    cli = ssm_cli([COMMAND, {"Status": "Success", "ResponseCode": 0, "StandardOutputContent": '{"items":['}])
    with pytest.raises(CollectionError, match="ssm_output_invalid_or_truncated"):
        run_recipe(cli, BASTION, PAYLOAD, lambda event: None)


def wait_for(manager, key):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        result = manager.get(key)
        if result["summary"]["state"] in {"finished", "cancelled"}:
            return result
        time.sleep(.01)
    pytest.fail("job did not finish")


class FakeCLI:
    def __init__(self, account, region, stop=None, deadline=None):
        self.region, self.stop, self.deadline = region, stop, deadline
        self.identity = {"Account": account.account_id, "Arn": "example"}

    def check(self):
        if self.stop.is_set():
            raise CollectionError("cancelled")


class FakeCollector(Collector):
    def aws(self):
        self.record("aws.cluster", [{"kind": "cluster", "name": self.cluster}])

    def kubernetes(self, log_target=None):
        self.record("kubernetes.pods", [], [{"code": "CrashLoopBackOff", "severity": "error"}],
                    complete=False, code="kubernetes_forbidden")


def test_multi_cluster_partial_findings_and_evidence(configured):
    store = EvidenceStore()
    manager = Investigations(store, cli_factory=FakeCLI, collector_factory=FakeCollector)
    start = manager.start("test", "us-east-1", ["one", "two"])
    result = wait_for(manager, start["investigation_id"])
    assert result["status"] == "partial"
    assert len(result["findings"]) == 2
    assert result["coverage"]["components_incomplete"] == 2
    evidence = store.get(result["evidence_id"])
    assert {i["cluster"] for i in evidence["items"]} == {"one", "two"}
    assert len(encoded(result)) <= 12288


def test_job_cancellation_preserves_existing_evidence(configured):
    ready = threading.Event()
    class Blocking(FakeCollector):
        def kubernetes(self, log_target=None):
            ready.set()
            self.cli.stop.wait(2)
            self.cli.check()
    manager = Investigations(EvidenceStore(), cli_factory=FakeCLI, collector_factory=Blocking)
    start = manager.start("test", "us-east-1", ["one"])
    assert ready.wait(2)
    manager.cancel(start["investigation_id"])
    result = wait_for(manager, start["investigation_id"])
    assert result["summary"]["state"] == "cancelled"
    assert result["coverage"]["complete"] is False
    assert result["evidence_id"]


def test_collector_pagination_failure_preserves_items():
    cli = FakeCLI(ACCOUNT, "us-east-1", threading.Event())
    def pages(*args):
        yield [{"id": "first"}]
        raise CollectionError("access_denied")
    cli.pages = pages
    collector = Collector(cli, "test", "one", lambda event: None)
    collector.listing("test", "eks", "anything", "key")
    assert collector.items[0]["data"]["id"] == "first"
    assert collector.coverage["test"]["complete"] is False


def test_empty_managed_nodegroups_not_a_failure():
    cli = FakeCLI(ACCOUNT, "us-east-1", threading.Event())
    def call(service, operation, parameters=None):
        assert operation == "describe-cluster"
        return {"cluster": {"name": "demo", "arn": PAYLOAD["cluster_arn"], "status": "ACTIVE", "computeConfig": {"enabled": True}}}
    cli.call = call
    cli.pages = lambda *args, **kwargs: iter([[]])
    collector = Collector(cli, "test", "demo", lambda event: None)
    collector.aws()
    assert not collector.findings
    assert all(c["complete"] for c in collector.coverage.values())


def test_expired_job_and_missing_config_are_explicit(monkeypatch):
    manager = Investigations(EvidenceStore())
    assert manager.get("missing")["status"] == "error"
    assert manager.start("missing", "us-east-1", ["demo"])["errors"][0]["code"] == "configuration_invalid"


def test_metric_absence_and_karpenter_version_gaps_are_not_healthy(monkeypatch):
    from aws_ops_mcp import eks_collect
    monkeypatch.setattr(eks_collect, "PATHS", {k: PATHS[k] for k in ["customresourcedefinitions", "nodepools", "node_metrics"]})
    monkeypatch.setattr(eks_collect, "resolve_bastion", lambda *a: BASTION)
    monkeypatch.setattr(eks_collect, "validate_bastion", lambda *a: None)
    def remote(cli, bastion, payload, emit):
        if payload["kind"] == "customresourcedefinitions":
            return {"complete": True, "items": [{"kind": "customresourcedefinitions", "name": "nodepools.karpenter.sh", "served_versions": ["v1beta1"]}]}
        return {"complete": False, "error": "api_not_found", "items": []}
    monkeypatch.setattr(eks_collect, "run_recipe", remote)
    collector = Collector(FakeCLI(ACCOUNT, "us-east-1", threading.Event()), "test", "demo", lambda e: None)
    collector.cluster_data = {"arn": PAYLOAD["cluster_arn"]}
    collector.kubernetes()
    assert collector.coverage["kubernetes.nodepools"]["complete"] is False
    assert collector.coverage["kubernetes.node_metrics"]["complete"] is False


def test_job_limit_and_ttl(configured):
    class Blocking(FakeCollector):
        def kubernetes(self, log_target=None):
            self.cli.stop.wait(2)
            self.cli.check()
    now = [0]
    manager = Investigations(EvidenceStore(), cli_factory=FakeCLI, collector_factory=Blocking, clock=lambda: now[0])
    first = manager.start("test", "us-east-1", ["one"])
    second = manager.start("test", "us-east-1", ["two"])
    assert manager.start("test", "us-east-1", ["three"])["errors"][0]["code"] == "investigation_capacity_reached"
    for start in (first, second):
        manager.cancel(start["investigation_id"])
        wait_for(manager, start["investigation_id"])
    now[0] = 901
    assert manager.get(first["investigation_id"])["errors"][0]["code"] == "investigation_missing_or_expired"


def test_inventory_continues_after_one_cluster_denied(configured):
    class InventoryCLI(FakeCLI):
        def pages(self, *a):
            yield ["denied", "allowed"]
        def call(self, service, operation, params):
            if params["name"] == "denied":
                raise CollectionError("access_denied")
            return {"cluster": {"name": "allowed", "status": "ACTIVE"}}
    manager = Investigations(EvidenceStore(), cli_factory=InventoryCLI)
    start = manager.start("test", "us-east-1", inventory=True)
    result = wait_for(manager, start["investigation_id"])
    assert result["status"] == "partial"
    assert result["coverage"]["components_observed"] == 2
    evidence = manager.store.get(result["evidence_id"])
    assert any(i.get("data", {}).get("name") == "allowed" for i in evidence["items"])


def test_aws_parameters_against_botocore_models():
    import botocore.session
    from botocore.validate import validate_parameters
    session = botocore.session.get_session()
    class ShapeCLI(FakeCLI):
        def validate(self, service, operation, params):
            name = "".join(part.title() for part in operation.split("-"))
            model = session.get_service_model(service)
            validate_parameters(params or {}, model.operation_model(name).input_shape)
        def call(self, service, operation, params=None):
            self.validate(service, operation, params)
            if operation == "describe-cluster":
                return {"cluster": {"status": "ACTIVE", "roleArn": "arn:aws:iam::000000000000:role/read",
                                    "resourcesVpcConfig": {"vpcId": "vpc-00000000"}}}
            if operation == "get-role":
                return {"Role": {"RoleName": "read"}}
            if operation == "describe-nodegroup":
                return {"nodegroup": {"status": "ACTIVE", "resources": {"autoScalingGroups": [{"name": "group"}]}}}
            if operation == "describe-addon":
                return {"addon": {"status": "ACTIVE"}}
            if operation == "describe-fargate-profile":
                return {"fargateProfile": {"status": "ACTIVE"}}
            if operation == "describe-target-health":
                return {"TargetHealthDescriptions": []}
            raise AssertionError(operation)
        def pages(self, service, operation, key, params=None, token=None, output_token=None):
            self.validate(service, operation, params)
            if operation == "list-nodegroups":
                yield ["nodes"]
            elif operation == "list-addons":
                yield ["coredns"]
            elif operation == "list-fargate-profiles":
                yield ["profile"]
            elif operation == "list-access-entries":
                yield ["arn:aws:iam::000000000000:role/read"]
            elif operation == "describe-load-balancers":
                yield [{"DNSName": "lb.example", "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:000000000000:loadbalancer/app/demo/1234567890123456"}]
            elif operation == "describe-target-groups":
                yield [{"TargetGroupArn": "arn:aws:elasticloadbalancing:us-east-1:000000000000:targetgroup/demo/1234567890123456"}]
            else:
                yield []
    collector = Collector(ShapeCLI(ACCOUNT, "us-east-1", threading.Event()), "test", "demo", lambda e: None)
    collector.aws()
    collector.dependencies([{"kind": "nodes", "provider_id": "aws:///us-east-1a/i-00000000000000001"},
                            {"kind": "persistentvolumes", "csi": {"driver": "ebs.csi.aws.com", "volumeHandle": "vol-00000000000000001"}},
                            {"kind": "services", "load_balancer": {"ingress": [{"hostname": "lb.example"}]}}])
    assert all(c["complete"] for c in collector.coverage.values())
