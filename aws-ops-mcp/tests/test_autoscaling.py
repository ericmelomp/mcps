from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock
import json
import pytest
import botocore.session
from botocore.validate import validate_parameters
from botocore.exceptions import ClientError
from aws_ops_mcp.platform_ops import Platform
from aws_ops_mcp.evidence import EvidenceStore

ARN = 'arn:aws:autoscaling:us-east-1:000000000000:autoScalingGroup:abc:autoScalingGroupName/demo'
ID = 'i-00000001'


class API:
    def __init__(self):
        self.calls = []
        self.group = {'AutoScalingGroupName': 'demo', 'AutoScalingGroupARN': ARN,
            'MinSize': 1, 'DesiredCapacity': 2, 'MaxSize': 2,
            'Instances': [{'InstanceId': ID, 'HealthStatus': 'Healthy', 'LifecycleState': 'InService',
                           'WeightedCapacity': '2'}], 'Tags': [{'Value': 'SECRET'}]}
        self.activities = {'Activities': [{'ActivityId': 'abc', 'AutoScalingGroupName': 'demo',
            'StartTime': datetime.now(timezone.utc)-timedelta(minutes=5), 'StatusCode': 'Failed',
            'Cause': 'SECRET', 'StatusMessage': 'SECRET'}]}
        self.ec2 = {'Reservations': [{'Instances': [{'InstanceId': ID, 'InstanceLifecycle': 'spot', 'UserData': 'SECRET'}]}]}

    def check(self, service, name, params):
        model = botocore.session.get_session().get_service_model(service)
        validate_parameters(params, model.operation_model(name).input_shape)
        self.calls.append((service, name, params))

    def describe_auto_scaling_groups(self, **params):
        self.check('autoscaling', 'DescribeAutoScalingGroups', params)
        return {'AutoScalingGroups': [self.group]}

    def describe_scaling_activities(self, **params):
        self.check('autoscaling', 'DescribeScalingActivities', params)
        return self.activities

    def describe_instances(self, **params):
        self.check('ec2', 'DescribeInstances', params)
        return self.ec2


def query(api):
    session = MagicMock(); session.client.return_value = api
    platform = Platform(EvidenceStore(), factory=lambda *args: (session, None))
    return platform.query('test', 'us-east-1', 'autoscaling', group_name='demo')


def codes(result):
    return {row['code'] for row in result['findings']}


def test_weighted_capacity_spot_and_failure_without_secrets(configured):
    api = API(); result = query(api)
    assert result['coverage']['complete']
    assert result['summary']['healthy_in_service_capacity'] == 2
    assert result['summary']['capacity_type_counts'] == {'spot': 1}
    assert 'asg_healthy_in_service_capacity_below_desired' not in codes(result)
    assert {'asg_at_configured_ceiling', 'asg_recent_scaling_failure'} <= codes(result)
    assert 'SECRET' not in json.dumps(result)
    assert not result['summary']['scaling_root_cause_verified']


def test_unhealthy_capacity_and_suspended_processes(configured):
    api = API(); api.group['Instances'][0]['HealthStatus'] = 'Unhealthy'
    api.group['SuspendedProcesses'] = [{'ProcessName': 'Launch', 'SuspensionReason': 'SECRET'}]
    result = query(api)
    assert {'asg_instance_unhealthy','asg_suspended_processes','asg_healthy_in_service_capacity_below_desired'} <= codes(result)
    assert 'SECRET' not in json.dumps(result)


def test_vcpu_without_weight_is_unknown_not_instance_count(configured):
    api = API(); api.group['DesiredCapacityType'] = 'vcpu'
    del api.group['Instances'][0]['WeightedCapacity']
    result = query(api)
    assert result['status'] == 'partial'
    assert result['summary']['healthy_in_service_capacity'] is None
    assert 'asg_healthy_in_service_capacity_below_desired' not in codes(result)


def test_partial_ec2_does_not_guess_on_demand(configured):
    api = API(); api.ec2 = {'Reservations': []}
    result = query(api)
    assert result['status'] == 'partial' and result['summary']['capacity_type_counts'] == {}


def test_on_demand_default_and_empty_group_no_broad_ec2_call(configured):
    api = API(); del api.ec2['Reservations'][0]['Instances'][0]['InstanceLifecycle']
    assert query(api)['summary']['capacity_type_counts'] == {'on-demand': 1}
    api.group['Instances'] = []; api.calls = []
    assert query(api)['summary']['capacity_type_counts'] == {}
    assert not any(s == 'ec2' for s, _, _ in api.calls)


@pytest.mark.parametrize('kind', ['scope', 'name', 'duplicate', 'capacity', 'limit'])
def test_rejects_bad_or_out_of_scope_data_before_ec2(configured, kind):
    api = API()
    if kind == 'scope': api.group['AutoScalingGroupARN'] = ARN.replace('000000000000', '111111111111')
    if kind == 'name': api.group['AutoScalingGroupName'] = 'other'
    if kind == 'duplicate': api.group['Instances'] *= 2
    if kind == 'capacity': api.group['MinSize'] = None
    if kind == 'limit': api.group['Instances'] *= 101
    result = query(api)
    assert result['status'] == 'partial' or result['status'] == 'error'
    assert not any(s == 'ec2' for s, _, _ in api.calls)


def test_activity_truncation_and_stale_events(configured):
    api = API(); api.activities['NextToken'] = 'more'
    api.activities['Activities'][0]['StartTime'] -= timedelta(days=2)
    result = query(api)
    assert result['status'] == 'partial' and result['summary']['recent_activity_count'] == 0
    assert 'asg_recent_scaling_failure' not in codes(result)


def test_activity_denied_retains_group_metadata(configured):
    api = API()
    def denied(**params):
        raise ClientError({'Error': {'Code': 'AccessDenied', 'Message': 'SECRET'}}, 'DescribeScalingActivities')
    api.describe_scaling_activities = denied
    result = query(api)
    assert result['status'] == 'partial' and result['summary']['healthy_in_service_capacity'] == 2
    assert 'SECRET' not in json.dumps(result)


def test_invalid_input_does_not_authenticate():
    factory = MagicMock()
    result = Platform(EvidenceStore(), factory=factory).query('test', 'us-east-1', 'autoscaling', group_name='*')
    assert result['status'] == 'error'
    factory.assert_not_called()


def test_configured_weights_missing_from_instance_are_not_one_unit(configured):
    api = API()
    api.group['MixedInstancesPolicy'] = {'LaunchTemplate': {'Overrides': [{'WeightedCapacity': '2'}]}}
    del api.group['Instances'][0]['WeightedCapacity']
    result = query(api)
    assert result['status'] == 'partial' and result['summary']['healthy_in_service_capacity'] is None


@pytest.mark.parametrize('code', ['AccessDenied', 'Throttling', 'ExpiredToken'])
def test_group_failure_is_not_healthy(configured, code):
    api = API()
    def failure(**params):
        raise ClientError({'Error': {'Code': code, 'Message': 'SECRET'}}, 'DescribeAutoScalingGroups')
    api.describe_auto_scaling_groups = failure
    result = query(api)
    assert not result['coverage']['complete'] and 'SECRET' not in json.dumps(result)


def test_empty_group_response_and_mutable_operations_rejected(configured):
    from aws_ops_mcp.ops_runtime import ReadContext
    from aws_ops_mcp.eks_cli import CollectionError
    api = API(); api.describe_auto_scaling_groups = lambda **p: {'AutoScalingGroups': []}
    assert not query(api)['coverage']['complete']
    session = MagicMock()
    context = ReadContext('test','us-east-1',factory=lambda *a: (session,None))
    for service, operation in [('autoscaling','set_desired_capacity'),('compute-optimizer','update_enrollment_status')]:
        with pytest.raises(CollectionError, match='operation_not_permitted'):
            context.call(service, operation)
    session.client.assert_not_called()
