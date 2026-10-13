"""Targeted ASG assessment; capacity units are never assumed to be node counts."""
import re
from datetime import datetime, timezone, timedelta
from collections import Counter

from .eks_cli import CollectionError
from .ops_runtime import safe_error
from .resource_assessments import signal


def validate(group_name):
    if not isinstance(group_name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:/+=,@-]{0,254}', group_name):
        raise CollectionError('invalid_autoscaling_group_name')


def collect(context, result, group_name):
    groups = list(context.pages('autoscaling', 'describe_auto_scaling_groups', 'AutoScalingGroups',
                                AutoScalingGroupNames=[group_name], MaxRecords=1))
    if not groups:
        raise CollectionError('autoscaling_group_not_found')
    if len(groups) != 1 or groups[0].get('AutoScalingGroupName') != group_name:
        raise CollectionError('unexpected_autoscaling_group')
    group = groups[0]
    arn = group.get('AutoScalingGroupARN', '')
    prefix = f'arn:aws:autoscaling:{context.region}:{context.account_id}:autoScalingGroup:'
    if not arn.startswith(prefix) or not arn.endswith(':autoScalingGroupName/' + group_name):
        raise CollectionError('autoscaling_scope_mismatch')
    instances = group.get('Instances', [])
    if len(instances) > 100:
        raise CollectionError('autoscaling_instance_limit')
    ids = [row.get('InstanceId', '') for row in instances]
    if len(set(ids)) != len(ids) or any(not re.fullmatch(r'i-(?:[a-f0-9]{8}|[a-f0-9]{17})', i) for i in ids):
        raise CollectionError('invalid_autoscaling_instances')
    unit = group.get('DesiredCapacityType', 'units')
    if unit not in {'units', 'vcpu', 'memory-mib'}:
        raise CollectionError('unsupported_autoscaling_capacity_unit')
    desired, minimum, maximum = (group.get(k) for k in ('DesiredCapacity', 'MinSize', 'MaxSize'))
    if any(type(v) is not int or v < 0 for v in (desired, minimum, maximum)):
        raise CollectionError('invalid_autoscaling_capacity')
    suspended = [r['ProcessName'] for r in group.get('SuspendedProcesses', []) if r.get('ProcessName')]
    distribution = group.get('MixedInstancesPolicy', {}).get('InstancesDistribution', {})
    result['items'].append({'kind': 'autoscaling_group', 'resource_id': arn,
        'minimum': minimum, 'desired': desired, 'maximum': maximum, 'capacity_unit': unit,
        'observed_instances': len(instances), 'availability_zones': group.get('AvailabilityZones', []),
        'capacity_rebalance': group.get('CapacityRebalance'), 'suspended_processes': suspended,
        'configured_on_demand_base': distribution.get('OnDemandBaseCapacity'),
        'configured_on_demand_percentage_above_base': distribution.get('OnDemandPercentageAboveBaseCapacity'),
        'spot_allocation_strategy': distribution.get('SpotAllocationStrategy')})
    if not minimum <= desired <= maximum:
        signal(result, 'asg_capacity_bounds_inconsistent', arn, 'high', desired=desired, minimum=minimum, maximum=maximum)
    if desired == maximum and maximum > 0:
        signal(result, 'asg_at_configured_ceiling', arn, 'info', desired=desired, maximum=maximum)
    if suspended:
        signal(result, 'asg_suspended_processes', arn, processes=suspended)
    active_units = 0
    units_known = True
    overrides = group.get('MixedInstancesPolicy', {}).get('LaunchTemplate', {}).get('Overrides', [])
    weighted = any('WeightedCapacity' in override for override in overrides)
    for instance in instances:
        weight = instance.get('WeightedCapacity', '1' if unit == 'units' and not weighted else None)
        if not instance.get('HealthStatus') or not instance.get('LifecycleState'):
            units_known = False
        if weight is None or not re.fullmatch(r'[1-9][0-9]*', str(weight)):
            units_known = False
        elif instance.get('LifecycleState') == 'InService' and instance.get('HealthStatus') == 'Healthy':
            active_units += int(weight)
        result['items'].append({'kind': 'asg_instance', 'resource_id': instance['InstanceId'],
            'lifecycle_state': instance.get('LifecycleState'), 'health': instance.get('HealthStatus'),
            'az': instance.get('AvailabilityZone'), 'weighted_capacity': weight})
        if instance.get('HealthStatus') == 'Unhealthy':
            signal(result, 'asg_instance_unhealthy', instance['InstanceId'])
    if not units_known:
        result['errors'].append({'code': 'asg_capacity_units_unobserved', 'component': 'capacity'})
    elif active_units < desired:
        signal(result, 'asg_healthy_in_service_capacity_below_desired', arn,
               active_capacity=active_units, desired=desired, capacity_unit=unit)
    lifecycles = Counter()
    if ids:
        try:
            observed = set()
            for reservation in context.pages('ec2', 'describe_instances', 'Reservations', InstanceIds=ids):
                for instance in reservation.get('Instances', []):
                    identifier = instance.get('InstanceId')
                    if identifier not in ids or identifier in observed:
                        raise CollectionError('unexpected_autoscaling_ec2_instance')
                    observed.add(identifier)
                    lifecycle = instance.get('InstanceLifecycle', 'on-demand')
                    lifecycles[lifecycle] += 1
                    result['items'].append({'kind': 'asg_ec2_lifecycle', 'resource_id': identifier,
                        'capacity_type': lifecycle, 'instance_type': instance.get('InstanceType'),
                        'state': instance.get('State', {}).get('Name')})
            if observed != set(ids):
                raise CollectionError('asg_ec2_selection_incomplete')
        except Exception as exc:
            result['errors'].append({'code': safe_error(exc), 'component': 'ec2_lifecycle'})
    now = datetime.now(timezone.utc)
    recent = 0
    try:
        response = context.call('autoscaling', 'describe_scaling_activities',
                                AutoScalingGroupName=group_name, IncludeDeletedGroups=False, MaxRecords=20)
        if response.get('NextToken') or len(response.get('Activities', [])) > 20:
            result['errors'].append({'code': 'asg_activity_sample_truncated', 'component': 'activities'})
        for activity in response.get('Activities', [])[:20]:
            if activity.get('AutoScalingGroupName') != group_name:
                raise CollectionError('unexpected_autoscaling_activity')
            stamp = activity.get('StartTime')
            if not isinstance(stamp, datetime) or stamp.tzinfo is None or stamp > now:
                raise CollectionError('invalid_autoscaling_activity_time')
            if stamp < now - timedelta(hours=24):
                continue
            recent += 1
            status = activity.get('StatusCode')
            result['items'].append({'kind': 'asg_recent_activity', 'resource_id': arn,
                'activity_id': activity.get('ActivityId'), 'started_at': stamp.isoformat(), 'status': status})
            if status in {'Failed', 'Cancelled'}:
                signal(result, 'asg_recent_scaling_failure', arn, activity_id=activity.get('ActivityId'), status=status)
    except Exception as exc:
        result['errors'].append({'code': safe_error(exc), 'component': 'activities'})
    result['summary'].update(assessment='autoscaling_configuration_and_snapshot',
        capacity_type_counts=dict(lifecycles), healthy_in_service_capacity=active_units if units_known else None,
        capacity_unit=unit, recent_activity_count=recent, application_health_verified=False,
        scaling_root_cause_verified=False)
    result['coverage']['exclusions'] = ['warm pools', 'scaling policies/schedules', 'launch template contents',
        'activity free text', 'metrics/rightsizing', 'application acceptance', 'Karpenter NodePools']
