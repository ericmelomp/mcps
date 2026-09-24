import boto3
from botocore.stub import Stubber

from aws_ops_mcp.ec2 import analyze, collect, normalize
from aws_ops_mcp.service import Service
from aws_ops_mcp.contracts import encoded


def raw_status(state="running", status="ok"):
    return {"InstanceId": "i-00000000000000001", "InstanceState": {"Name": state},
            "InstanceStatus": {"Status": status}, "SystemStatus": {"Status": "ok"}}


def test_pagination_and_safe_field_selection():
    client = boto3.client("ec2", region_name="us-east-1")
    events = []
    with Stubber(client) as stub:
        stub.add_response("describe_instances", {"Reservations": [{"Instances": [{
            "InstanceId": "i-00000000000000001", "State": {"Name": "running"},
            "Tags": [{"Key": "secret", "Value": "do-not-return"}]
        }]}], "NextToken": "next"}, {"MaxResults": 100})
        stub.add_response("describe_instances", {"Reservations": []}, {"MaxResults": 100, "NextToken": "next"})
        collect(client, False, events.append)
    assert len(events) == 2
    assert events[-1]["complete"]
    assert b"do-not-return" not in encoded(events)


def test_later_page_failure_retains_previous_page(configured):
    client = boto3.client("ec2", region_name="us-east-1")
    events = []
    with Stubber(client) as stub:
        stub.add_response("describe_instance_status", {"InstanceStatuses": [raw_status(status="impaired")], "NextToken": "next"},
                          {"MaxResults": 100, "IncludeAllInstances": True})
        stub.add_client_error("describe_instance_status", service_error_code="UnauthorizedOperation",
                              expected_params={"MaxResults": 100, "IncludeAllInstances": True, "NextToken": "next"})
        collect(client, True, events.append)
    result = Service(run=lambda *_: (events[0]["items"], [{"code": events[1]["code"]}], 1, False)).query("test", "us-east-1", True)
    assert result["status"] == "partial"
    assert result["findings"][0]["code"] == "status_check_failed"
    assert result["summary"]["counts_complete"] is False
    assert result["errors"] == [{"code": "access_denied"}]


def test_stopped_is_not_failure_and_missing_running_check_is_partial(configured):
    stopped = normalize(raw_status("stopped", "not-applicable"), True)
    assert analyze([stopped]) == ([], 0)
    missing = normalize({"InstanceId": "i-1", "InstanceState": {"Name": "running"}}, True)
    result = Service(run=lambda *_: ([missing], [], 1, True)).query("test", "us-east-1", True)
    assert result["status"] == "partial"
    assert not result["coverage"]["complete"]


def test_empty_success_is_distinct_from_denial(configured):
    empty = Service(run=lambda *_: ([], [], 1, True)).query("test", "us-east-1")
    denied = Service(run=lambda *_: ([], [{"code": "access_denied"}], 0, False)).query("test", "us-east-1")
    assert empty["status"] == "ok"
    assert denied["status"] == "error"


def test_output_is_bounded_and_full_evidence_is_available(configured):
    items = [normalize({"InstanceId": f"i-{i:017d}", "State": {"Name": "running"}}) for i in range(1000)]
    service = Service(run=lambda *_: (items, [], 10, True))
    result = service.query("test", "us-east-1")
    assert len(encoded(result)) <= 12288
    assert len(result["items"]) == 20
    assert result["summary"]["observed_instances"] == 1000
    page = service.store.get(result["evidence_id"])
    assert len(page["items"]) == 50
    assert page["next_offset"] == 50
    assert len(encoded(page)) <= 24576


def test_page_limit_is_explicit():
    class Client:
        def describe_instances(self, **kwargs):
            return {"Reservations": [], "NextToken": "more"}
    messages = []
    collect(Client(), False, messages.append, max_pages=1)
    assert messages[-1] == {"kind": "error", "code": "page_limit"}


def test_completed_event_and_non_applicable_ebs_are_not_failures():
    instance = raw_status()
    instance["AttachedEbsStatus"] = {"Status": "not-applicable"}
    instance["Events"] = [{"Code": "system-reboot", "Description": "[Completed] finished"}]
    assert analyze([normalize(instance, True)]) == ([], 0)


def test_multiple_unknowns_count_one_instance():
    instance = raw_status(status="initializing")
    instance["Events"] = [{"Code": "system-reboot"}] * 21
    _, unavailable = analyze([normalize(instance, True)])
    assert unavailable == 1
