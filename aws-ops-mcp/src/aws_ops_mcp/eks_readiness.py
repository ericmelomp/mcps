"""Conservative withdrawal and Spot resilience evidence; no drain simulation."""
from collections import Counter
from .eks_insights import node_group, requests, summarize


def selector_match(selector, labels):
    if selector.get('omitted'):
        return None
    if any(labels.get(k) != v for k, v in selector.get('match_labels', {}).items()):
        return False
    for e in selector.get('match_expressions', []):
        key, op, values = e.get('key'), e.get('operator'), e.get('values', [])
        if op == 'In' and labels.get(key) not in values: return False
        if op == 'NotIn' and key in labels and labels[key] in values: return False
        if op == 'Exists' and key not in labels: return False
        if op == 'DoesNotExist' and key in labels: return False
        if op not in {'In', 'NotIn', 'Exists', 'DoesNotExist'}: return None
    return True


def node_matches(scheduling, node):
    labels = node.get('labels', {})
    if scheduling.get('omitted_constraints'):
        return None
    if any(labels.get(k) != v for k, v in scheduling.get('node_selector', {}).items()):
        return False
    terms = scheduling.get('required_node_affinity', [])
    if terms:
        # Empty node selector term matches no nodes.
        values = [selector_match({'match_expressions': term}, labels) if term else False for term in terms]
        if True not in values: return None if None in values else False
    for t in node.get('taints', []):
        if t.get('effect') not in {'NoSchedule', 'NoExecute'}:
            continue
        def tolerated(x):
            if x.get('effect') and x['effect'] != t['effect']: return False
            op = x.get('operator', 'Equal')
            return (op == 'Exists' and (not x.get('key') or x['key'] == t['key'])) or (op == 'Equal' and x.get('key') == t['key'] and x.get('value', '') == t.get('value', ''))
        if not any(tolerated(x) for x in scheduling.get('tolerations', [])):
            return False
    return True


def controller_of(pod, rs):
    owner = next((o for o in pod.get('owners', []) if o.get('kind') != 'DaemonSet'), {})
    if owner.get('kind') == 'ReplicaSet':
        obj = rs.get((pod.get('namespace'), owner.get('name')), {})
        parent = next(iter(obj.get('owners', [])), None)
        if parent: return parent
    return owner


def assess(items, complete):
    nodes = [i for i in items if i.get('kind') == 'nodes']
    by_node = {n['name']: n for n in nodes}
    pods = [p for p in items if p.get('kind') == 'pods' and not p.get('deleting') and p.get('phase') not in {'Succeeded','Failed'}]
    rs = {(r['namespace'], r['name']): r for r in items if r.get('kind') == 'replicasets'}
    controllers = {(w['namespace'], w['name']): w for w in items if w.get('kind') in {'deployments','statefulsets','rollouts'}}
    pvcs = {(p['namespace'],p['name']): p for p in items if p.get('kind') == 'persistentvolumeclaims'}
    pvs = {p['name']:p for p in items if p.get('kind') == 'persistentvolumes'}
    pdbs = [p for p in items if p.get('kind') == 'poddisruptionbudgets']
    cap = {r['name']: r for r in summarize(items, complete) if r.get('kind') == 'node_capacity'}
    needed = {'nodes','pods','replicasets','deployments','statefulsets','poddisruptionbudgets','persistentvolumeclaims','persistentvolumes'}
    missing = sorted(needed-complete)
    rows = []
    grouped = {}
    for p in pods:
        owner = controller_of(p,rs)
        grouped.setdefault((p['namespace'],owner.get('kind'),owner.get('name') or p['name']),[]).append(p)
        src = by_node.get(p.get('node'))
        if src is None or node_group(src)['capacity_type'] != 'on-demand': continue
        if any(o.get('kind') == 'DaemonSet' for o in p.get('owners', [])): continue
        blockers, gaps = [], list(missing)
        if not any(c.get("type")=="Ready" and c.get("status")=="True" for c in p.get("conditions",[])):
            blockers.append("source_pod_not_ready")
        if not owner: blockers.append('unmanaged_pod')
        if owner.get('kind') == 'ReplicaSet': gaps.append('deployment_owner_unresolved')
        workload = controllers.get((p['namespace'],owner.get('name')))
        if workload and workload.get('desired',0) < 2: blockers.append('single_replica_workload')
        if p.get('local_storage'): blockers.append('local_storage_requires_review')
        if p.get('scheduling',{}).get('pod_affinity_present') or p.get('scheduling',{}).get('topology_spread_present'):
            gaps.append('pod_affinity_or_spread_not_simulated')
        for pdb in pdbs:
            if pdb.get('namespace') != p['namespace'] or pdb.get('selector_null'): continue
            match = selector_match(pdb.get('selector',{}),p.get('labels',{}))
            if match is None: gaps.append('pdb_selector_omitted')
            elif match and (pdb.get('disruptions_allowed') is None or pdb.get('observed_generation') is None or pdb.get('generation') != pdb.get('observed_generation')):
                gaps.append('pdb_status_stale_or_unknown')
            elif match and pdb.get('disruptions_allowed',0) <= 0: blockers.append('pdb_blocks_eviction')
        scheduling = p.get('scheduling',{})
        candidates = []
        unknown = False
        for n in nodes:
            if node_group(n)['capacity_type'] != 'spot' or n.get('unschedulable') or not any(c.get('type')=='Ready' and c.get('status')=='True' for c in n.get('conditions',[])): continue
            matches = node_matches(scheduling,n)
            unknown |= matches is None
            if matches is not True: continue
            zones_ok = True
            for claim in p.get('volumes',[]):
                pvc = pvcs.get((p['namespace'],claim))
                pv = pvs.get((pvc or {}).get('volume'))
                if not pvc or pvc.get('phase') != 'Bound' or not pv:
                    gaps.append('volume_topology_unknown'); zones_ok=False; continue
                affinity = pv.get('node_affinity',{})
                volume_match = node_matches(affinity,dict(n,taints=[]))
                if volume_match is None: gaps.append('volume_constraints_omitted')
                if volume_match is not True:
                    zones_ok=False
                # EBS without known AZ/topology must not be treated as portable.
                if pv.get('csi',{}).get('driver')=='ebs.csi.aws.com' and not affinity.get('required_node_affinity'):
                    gaps.append('ebs_zone_unknown'); zones_ok=False
            if zones_ok: candidates.append(n)
        if unknown: gaps.append('scheduling_constraints_omitted')
        if not candidates and not unknown: blockers.append('no_existing_spot_node_matches')
        try: req=requests(p)
        except ValueError: req=None
        fitting=[]
        for n in candidates:
            resource=cap.get(n['name'],{}).get('resources',{})
            if req is None or any(resource.get(k,{}).get('request_headroom') is None for k in ('cpu','memory')):
                gaps.append('request_headroom_unknown'); continue
            if all(req[k] <= resource[k]['request_headroom'] for k in ('cpu','memory')): fitting.append(n['name'])
        if candidates and req is not None and not fitting and 'request_headroom_unknown' not in gaps:
            blockers.append('insufficient_current_request_headroom')
        rows.append({'kind':'withdrawal_workload','namespace':p['namespace'],'name':p['name'],'source_node':p.get('node'),
                     'owner':owner,'blockers':sorted(set(blockers)),'gaps':sorted(set(gaps)),
                     'candidate_nodes':fitting[:10], 'candidate_count':len(fitting),
                     'assessment':'blocked' if blockers else 'requires_review',
                     'scope':'individual fit on current Spot nodes; no joint packing or future provisioning simulation'})
    resilience=[]
    for (ns,kind,name), members in grouped.items():
        spot=[p for p in members if node_group(by_node.get(p.get('node'),{}))['capacity_type']=='spot']
        if not spot: continue
        node_names = sorted({p.get('node') for p in members if p.get('node')})
        zones = sorted({by_node.get(p.get('node'),{}).get('labels',{}).get('topology.kubernetes.io/zone') for p in members} - {None})
        risks=[]
        if len(members)==1: risks.append('single_observed_replica')
        if len(members)>1 and len(node_names)==1: risks.append('replicas_on_single_node')
        if len(zones)==1: risks.append('single_observed_az')
        if not zones: risks.append('zone_unknown')
        if any(marker in name.lower() for marker in ('karpenter','coredns','argocd','traefik','cert-manager','controller')):
            risks.append('management_component_on_spot_name_based')
        if risks: resilience.append({'kind':'spot_workload_risk','namespace':ns,'name':name,'owner_kind':kind,
                                      'replicas_observed':len(members),'spot_replicas':len(spot),'nodes':node_names[:10], 'zones':zones,'risks':risks})
    pools={}
    for n in nodes:
        g=node_group(n)
        if g['capacity_type']=='spot':
            pools.setdefault(g['pool'],Counter())[n.get('labels',{}).get('topology.kubernetes.io/zone','unknown')]+=1
    return [{'kind':'withdrawal_summary','complete':not missing,'workloads_remaining':len(rows),
             'blocked_workloads':sum(bool(r['blockers']) for r in rows),'coverage_gaps':missing,
             'drain_authorized':False,'joint_scheduler_simulation':False},
            {'kind':'spot_resilience_summary','complete':{'nodes','pods','replicasets'}<=complete,
             'pools':[{'pool':k,'nodes_by_zone':dict(v)} for k,v in list(pools.items())[:20]],
             'pool_count':len(pools),'pools_truncated':len(pools)>20, 'risk_count':len(resilience),'fault_injection_performed':False}, *rows,*resilience]
