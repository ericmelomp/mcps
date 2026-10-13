"""Deterministic EKS capacity and placement summaries; never a drain approval."""
from decimal import Decimal, InvalidOperation
import re


def quantity(value):
    match = re.fullmatch(r'([+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)(Ki|Mi|Gi|Ti|Pi|Ei|n|u|m|k|K|M|G|T|P|E)?', str(value))
    if not match:
        raise ValueError('invalid_quantity')
    suffix = match[2] or ''
    factors = {'': 1, 'n': 1e-9, 'u': 1e-6, 'm': 1e-3, 'k': 1e3, 'K': 1e3,
               **{x: 1000**(i+2) for i, x in enumerate('MGTPE')},
               **{x+'i': 1024**(i+1) for i, x in enumerate('KMGTPE')}}
    try:
        result = float(Decimal(match[1]) * Decimal(str(factors[suffix])))
        if result < 0 or not result < float('inf'):
            raise ValueError('invalid_quantity')
        return result
    except InvalidOperation:
        raise ValueError('invalid_quantity') from None


def requests(pod):
    if pod.get('pod_resources_present'):
        return None  # Pod-level resources require their own scheduler semantics.
    result = {}
    for resource in ('cpu', 'memory'):
        def req(c):
            r = c.get('requests', {})
            # API normally defaults missing requests from limits.
            return quantity(r.get(resource, c.get('limits', {}).get(resource, '0')))
        containers = pod.get('resources', [])
        app = sum(req(c) for c in containers if not c.get('init'))
        sidecars, peak = 0, 0
        for c in containers:
            if not c.get('init'):
                continue
            if c.get('restart_policy') == 'Always':
                sidecars += req(c)
                peak = max(peak, sidecars)
            else:
                peak = max(peak, sidecars + req(c))
        result[resource] = max(app + sidecars, peak) + quantity(pod.get('overhead', {}).get(resource, '0'))
    return result


def node_group(node):
    labels = node.get('labels', {})
    capacity = labels.get('karpenter.sh/capacity-type') or labels.get('eks.amazonaws.com/capacityType') or node.get('ec2_capacity_type')
    sources = {str(labels[k]).lower().replace('_', '-') for k in ('karpenter.sh/capacity-type', 'eks.amazonaws.com/capacityType') if labels.get(k)}
    if node.get('ec2_capacity_type') and node['ec2_capacity_type'] != 'unknown':
        sources.add(node['ec2_capacity_type'])
    if len(sources) > 1:
        capacity = 'unknown'
    return {'pool': labels.get('karpenter.sh/nodepool') or labels.get('eks.amazonaws.com/nodegroup') or 'unknown',
            'capacity_type': str(capacity or 'unknown').lower().replace('_', '-'),
            'tier': labels.get('workload-tier', 'unknown')}


def summarize(items, complete_kinds):
    nodes = [x for x in items if x.get('kind') == 'nodes']
    pods = [x for x in items if x.get('kind') == 'pods' and not x.get('deleting') and x.get('phase') not in {'Succeeded', 'Failed'}]
    metrics = {x['name']: x for x in items if x.get('kind') == 'node_metrics'}
    rows, totals = [], {}
    for node in nodes:
        placement = node_group(node)
        assigned = [p for p in pods if p.get('node') == node['name']]
        bucket = totals.setdefault((placement['pool'], placement['capacity_type'], placement['tier']), {'nodes': 0, 'pods': 0, 'daemonset_pods': 0, 'stateful_pods': 0})
        bucket['nodes'] += 1
        bucket['pods'] += len(assigned)
        bucket['daemonset_pods'] += sum(any(o.get('kind') == 'DaemonSet' for o in p.get('owners', [])) for p in assigned)
        bucket['stateful_pods'] += sum(any(o.get('kind') == 'StatefulSet' for o in p.get('owners', [])) for p in assigned)
        resource_rows, gaps = {}, ([] if "pods" in complete_kinds else ["pod_coverage_incomplete"])
        effective = []
        for p in assigned:
            try:
                r = requests(p)
                if r is None:
                    gaps.append('pod_level_resources_unsupported')
                else:
                    effective.append((p, r))
            except ValueError:
                gaps.append('invalid_resource_quantity')
        for resource in ('cpu', 'memory'):
            try:
                alloc = quantity(node.get('allocatable', {})[resource])
                requested = sum(r[resource] for _, r in effective)
                ds = sum(r[resource] for p, r in effective if any(o.get('kind') == 'DaemonSet' for o in p.get('owners', [])))
                usage = metrics.get(node['name'], {}).get('usage', {}).get(resource)
                used = quantity(usage) if usage is not None else None
                resource_rows[resource] = {'allocatable': alloc, 'requests': requested if not gaps else None,
                    'request_headroom': alloc-requested if not gaps else None, 'daemonset_requests': ds,
                    'usage': used, 'usage_percent': round(100*used/alloc, 1) if used is not None and alloc else None}
            except (ValueError, KeyError):
                gaps.append('resource_data_unavailable')
        rows.append({'kind': 'node_capacity', 'name': node['name'], **placement, 'resources': resource_rows,
                     'metrics_timestamp': metrics.get(node['name'], {}).get('timestamp'), 'gaps': sorted(set(gaps)),
                     'pods': len(assigned), 'requests_complete': 'pods' in complete_kinds and not gaps})
    placements = [{**dict(zip(('pool', 'capacity_type', 'tier'), key)), **value} for key, value in totals.items()]
    remaining = []
    indexed = {n['name']: node_group(n) for n in nodes}
    for p in pods:
        place = indexed.get(p.get('node'), {'capacity_type': 'unknown', 'pool': 'unknown', 'tier': 'unknown'})
        if place['capacity_type'] in {'on-demand', 'unknown'}:
            remaining.append({'namespace': p['namespace'], 'name': p['name'], 'node': p.get('node'),
                              'owners': p.get('owners', []), **place, 'volumes': p.get('volumes', []),
                              'scheduling': p.get('scheduling', {})})
    summary = {'kind': 'migration_summary', 'complete': {'nodes', 'pods'} <= complete_kinds,
               'placement': placements[:10], 'placement_count': len(placements), 'placement_truncated': len(placements)>10, 'remaining_count': len(remaining), 'remaining': [{k: r[k] for k in ('namespace', 'name', 'node', 'pool', 'capacity_type')} for r in remaining[:3]],
               'remaining_truncated': len(remaining) > 3, 'unscheduled_pods': sum(not p.get('node') for p in pods),
               'withdrawal_assessment': 'not_assessed', 'functional_tests': 'not_performed',
               'restart_interpretation': 'cumulative_only_no_baseline'}
    largest = []
    for pod in pods:
        try:
            r = requests(pod)
        except ValueError:
            r = None
        if r is not None:
            largest.append({'namespace': pod['namespace'], 'name': pod['name'], 'requests': r})
    summary['largest_pods_by_memory_requests'] = sorted(largest, key=lambda p: p['requests']['memory'], reverse=True)[:3]
    return [summary, *rows, *[{'kind': 'remaining_workload', **x} for x in remaining]]


def restart_snapshot(items):
    return {(p.get('namespace'), p.get('name'), p['uid'], c.get('name')): c.get('restarts', 0)
            for p in items if p.get('kind') == 'pods' and p.get('uid')
            for c in p.get('containers', [])}


def restart_delta(current, previous):
    compared = increases = resets = 0
    for key, count in current.items():
        if key not in previous:
            continue
        if count < previous[key]:
            resets += 1
            continue
        compared += 1
        increases += count-previous[key]
    return {'compared_containers': compared, 'new_or_recreated_containers': len(set(current)-set(previous)),
            'counter_resets': resets, 'restart_increase': increases,
            'scope': 'same pod UID only; no inference for recreated pods'}
