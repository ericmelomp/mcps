"""Observed EC2 recommendations, never automatic resizing or realized savings."""
import math
import re
from datetime import datetime, timezone
from .eks_cli import CollectionError
from .resource_assessments import signal


def validate(instance_ids, maximum_age_hours=168):
    if not isinstance(instance_ids, list) or not 1 <= len(instance_ids) <= 5 or len(set(instance_ids)) != len(instance_ids):
        raise CollectionError('invalid_optimizer_selection')
    if any(not isinstance(i, str) or not re.fullmatch(r'i-(?:[a-f0-9]{8}|[a-f0-9]{17})', i) for i in instance_ids):
        raise CollectionError('invalid_optimizer_selection')
    if type(maximum_age_hours) is not int or not 1 <= maximum_age_hours <= 8760:
        raise CollectionError('invalid_recommendation_age')


def number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise CollectionError('invalid_optimizer_numeric_value')
    return value


def collect(context, result, instance_ids, maximum_age_hours=168):
    arns = [f'arn:aws:ec2:{context.region}:{context.account_id}:instance/{i}' for i in instance_ids]
    response = context.call('compute-optimizer', 'get_ec2_instance_recommendations',
        instanceArns=arns, accountIds=[context.account_id], maxResults=5)
    if response.get('nextToken'):
        result['errors'].append({'code': 'optimizer_response_truncated', 'component': 'recommendations'})
    if response.get('errors'):
        result['errors'].append({'code': 'optimizer_resource_errors', 'component': 'recommendations'})
    rows = response.get('instanceRecommendations', [])
    if len(rows) > 5:
        raise CollectionError('optimizer_recommendation_limit')
    observed = set()
    now = datetime.now(timezone.utc)
    for row in rows:
        arn = row.get('instanceArn')
        if arn not in arns or row.get('accountId') != context.account_id or arn in observed:
            raise CollectionError('optimizer_scope_or_duplicate_mismatch')
        observed.add(arn)
        stamp = row.get('lastRefreshTimestamp')
        if not isinstance(stamp, datetime) or stamp.tzinfo is None or stamp > now:
            raise CollectionError('invalid_optimizer_refresh_time')
        age = (now - stamp).total_seconds() / 3600
        metrics = row.get('utilizationMetrics', [])
        memory = any(m.get('name') == 'Memory' and m.get('statistic') in {'Maximum', 'Average'}
                     and number(m.get('value')) >= 0 for m in metrics)
        options = []
        for option in row.get('recommendationOptions', [])[:3]:
            options.append({'instance_type': option.get('instanceType'), 'rank': option.get('rank'),
                'performance_risk': number(option['performanceRisk']) if 'performanceRisk' in option else None,
                'platform_differences': option.get('platformDifferences', []),
                'migration_effort': option.get('migrationEffort')})
        result['items'].append({'kind': 'ec2_optimizer_recommendation', 'resource_id': arn,
            'current_instance_type': row.get('currentInstanceType'), 'finding': row.get('finding'),
            'reason_codes': row.get('findingReasonCodes', []), 'refreshed_at': stamp.isoformat(),
            'age_hours': age, 'lookback_days': number(row['lookBackPeriodInDays']) if 'lookBackPeriodInDays' in row else None,
            'memory_metric_observed': memory, 'options': options})
        if age > maximum_age_hours:
            signal(result, 'optimizer_recommendation_stale', arn, age_hours=age, maximum_age_hours=maximum_age_hours)
        if not memory:
            signal(result, 'optimizer_memory_metric_unobserved', arn, 'info')
        if row.get('finding') in {'Underprovisioned', 'UNDER_PROVISIONED', 'Overprovisioned', 'OVER_PROVISIONED', 'NotOptimized'}:
            signal(result, 'optimizer_sizing_review_recommended', arn, 'info', 'possible', aws_finding=row.get('finding'))
        if any('Architecture' in o['platform_differences'] for o in options):
            signal(result, 'optimizer_architecture_compatibility_review', arn, 'info', 'possible')
    if observed != set(arns):
        result['errors'].append({'code': 'optimizer_selection_incomplete', 'component': 'recommendations'})
    result['summary'].update(assessment='aws_compute_optimizer_observations', observed_recommendations=len(observed),
        rightsizing_verified=False, realized_savings_verified=False, maximum_age_hours=maximum_age_hours)
    result['coverage']['exclusions'] = ['automatic resizing/enrollment', 'estimated or realized savings',
        'application performance acceptance', 'pod-level recommendations', 'ASG/EBS/Lambda recommendations']
