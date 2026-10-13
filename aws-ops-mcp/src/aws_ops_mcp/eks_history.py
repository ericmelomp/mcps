"""Bounded in-memory health history. No client data is written to disk."""
from .eks_insights import restart_snapshot, restart_delta


def snapshot(items):
    return {'restarts': restart_snapshot(items),
            'nodes': {i['name']: next((c.get('status') for c in i.get('conditions',[]) if c.get('type')=='Ready'),None)
                      for i in items if i.get('kind')=='nodes'},
            'containers': {(p.get('namespace'),p.get('name'),p['uid'],c.get('name')):
                           (c.get('waiting'),c.get('last_terminated'),c.get('last_finished_at'))
                           for p in items if p.get('kind')=='pods' and p.get('uid') for c in p.get('containers',[])},
            'events': {(i.get('namespace'),i.get('name')): (i.get('reason'),i.get('count',1),i.get('last_seen'))
                       for i in items if i.get('kind')=='events' and i.get('type')=='Warning'}}


def compare(current, previous):
    current_nodes, old_nodes=current['nodes'],previous['nodes']
    changed=[]
    for key,value in current['containers'].items():
        old=previous['containers'].get(key)
        if old and value!=old:
            code='waiting_state_changed' if value[0]!=old[0] else 'termination_changed'
            if value[1]=='OOMKilled' and value[2] and value[2]!=old[2]: code='new_oom_termination'
            changed.append({'namespace':key[0],'pod':key[1],'container':key[3],'code':code,'waiting':value[0],
                            'last_termination':value[1], 'finished_at':value[2]})
    warnings=[]
    for key,value in current['events'].items():
        old=previous['events'].get(key)
        if old is None or value[1]>old[1] or value[2]!=old[2]:
            warnings.append({'namespace':key[0],'name':key[1],'reason':value[0],
                             'count_increase':value[1]-old[1] if old and value[1]>=old[1] else None,
                             'interpretation':'first_observed' if old is None else 'updated_event'})
    return {'kind':'health_comparison', 'baseline_available':True,
            'restarts':restart_delta(current['restarts'],previous['restarts']),
            'added_nodes':sorted(set(current_nodes)-set(old_nodes))[:5],
            'removed_nodes':sorted(set(old_nodes)-set(current_nodes))[:5],
            'new_not_ready_nodes':[n for n,r in current_nodes.items() if r!='True' and old_nodes.get(n)=='True'][:5],
            'container_changes':changed[:3], 'container_change_count':len(changed),
            'warning_changes':warnings[:3],'warning_change_count':len(warnings),
            'output_truncated':len(warnings)>3 or len(changed)>3 or len(set(current_nodes)^set(old_nodes))>5,
            'scope':'two complete snapshots; first observation is not proof of recent failure'}
