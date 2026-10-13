"""Local JSON plan review; input values may be secret and are never echoed."""
import json
import re
from collections import Counter
from .contracts import envelope,bounded
from .eks_cli import CollectionError


def has_unknown(value,depth=0):
    if depth>30:raise CollectionError('unknown_mask_depth_limit')
    if isinstance(value,bool):return value
    if isinstance(value,dict):return any(has_unknown(v,depth+1) for v in value.values())
    if isinstance(value,list):return any(has_unknown(v,depth+1) for v in value)
    raise CollectionError('invalid_unknown_mask')


def query(plan_json):
    result=envelope();result['items']=[]
    try:
        if not isinstance(plan_json,str) or len(plan_json)>2*1024*1024:raise CollectionError('plan_size_limit')
        plan=json.loads(plan_json)
        if not isinstance(plan,dict) or not re.fullmatch(r'1\.\d+',str(plan.get('format_version',''))):
            raise CollectionError('unsupported_plan_format')
        changes=plan.get('resource_changes',[])
        if not isinstance(changes,list) or len(changes)>1000:raise CollectionError('plan_resource_limit')
        counts=Counter();unknown=0
        for index,resource in enumerate(changes):
            if not isinstance(resource,dict) or resource.get('mode','managed')!='managed':continue
            change=resource.get('change',{})
            actions=change.get('actions')
            if actions not in [['no-op'],['create'],['read'],['update'],['delete'],['delete','create'],['create','delete'],['forget'],['create','forget']]:
                raise CollectionError('unsupported_plan_actions')
            label='replace' if len(actions)==2 and 'delete' in actions else '+'.join(actions)
            counts[label]+=1;after=change.get('after');unknown_fields=change.get('after_unknown',{})
            unknown += has_unknown(unknown_fields)
            type_=resource.get('type')
            if not isinstance(type_,str) or not re.fullmatch(r'[a-z][a-z0-9_]{0,127}',type_):
                raise CollectionError('invalid_resource_type')
            # Index links back to supplied plan without exposing addresses/for_each keys or values.
            row={'kind':'planned_resource','resource_index':index,'resource_type':resource.get('type'),
                 'action':label,'unknown_values_present':has_unknown(unknown_fields)}
            result['items'].append(row)
            def finding(code,severity='warning',confidence='confirmed'):
                result['findings'].append({'code':code,'severity':severity,'confidence':confidence,
                    'evidence':{'resource_index':index,'resource_type':resource.get('type')},
                    'recommendations':['Review change impact and verify sensitive/unknown attributes in the original plan']})
            if 'delete' in actions:finding('planned_destruction_or_replacement','high')
            if actions==['forget'] or 'forget' in actions:finding('planned_state_removal')
            if not isinstance(after,dict) or not any(a in actions for a in ('create','update')):continue
            def known(key):return not (unknown_fields is True or isinstance(unknown_fields,dict) and has_unknown(unknown_fields.get(key,False)))
            if type_ in {'aws_db_instance','aws_rds_cluster','aws_ebs_volume'} and known('storage_encrypted' if type_!='aws_ebs_volume' else 'encrypted'):
                key='encrypted' if type_=='aws_ebs_volume' else 'storage_encrypted'
                if after.get(key) is False:finding('planned_storage_encryption_disabled','high')
            if type_=='aws_db_instance' and known('publicly_accessible') and after.get('publicly_accessible') is True:
                finding('planned_database_public_access','warning','possible')
            if type_=='aws_s3_bucket_public_access_block' and all(known(k) for k in ('block_public_acls','ignore_public_acls','block_public_policy','restrict_public_buckets')):
                if any(after.get(k) is False for k in ('block_public_acls','ignore_public_acls','block_public_policy','restrict_public_buckets')):
                    finding('planned_bucket_public_access_block_relaxed','warning','possible')
        result['summary']={'actions':dict(counts),'managed_resources':len(result['items']),'resources_with_unknown_values':unknown,
            'assessment':'proposed_plan_signals_only','live_drift_verified':False,'apply_executed':False,
            'finding_count':len(result['findings']),'input_drift_entries':len(plan.get('resource_drift',[])) if isinstance(plan.get('resource_drift',[]),list) else None}
        if result['findings']:result['status']='degraded'
    except Exception as exc:
        result.update(status='error',errors=[{'code':exc.code if isinstance(exc,CollectionError) else 'invalid_plan_json'}])
        result['coverage']['complete']=False
    result['coverage']['exclusions']=['live drift/state comparison','Terraform execution','full provider schema/policy validation',
        'raw values/addresses/outputs/sensitive markers','pipeline/OIDC review','replacement downtime verification']
    return bounded(result)
