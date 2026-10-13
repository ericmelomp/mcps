import json
import threading
from unittest.mock import MagicMock

import pytest
from aws_ops_mcp.eks_insights import quantity, requests, node_group, summarize
from aws_ops_mcp.eks_kubernetes import normalize, analyze, PATHS
from aws_ops_mcp.eks_collect import Collector, PROFILES
from aws_ops_mcp.eks_jobs import Investigations
from aws_ops_mcp.evidence import EvidenceStore
from aws_ops_mcp.eks_ssm import recipe


def test_normalization_does_not_export_specs_secrets_or_unknown_labels():
    spec = {'nodeSelector': {'workload-tier': 'apps', 'tenant-secret': 'NEVER_RETURN'},
            'containers': [{'name': 'app', 'env': [{'name': 'TOKEN', 'value': 'NEVER_RETURN'}]}],
            'affinity': {'nodeAffinity': {'requiredDuringSchedulingIgnoredDuringExecution': {'nodeSelectorTerms': [
                {'matchExpressions': [{'key':'workload-tier', 'operator':'In', 'values':['apps']},
                                      {'key':'secret', 'operator':'In', 'values':['NEVER_RETURN']}]}]}}}}
    pod = normalize('pods', {'metadata': {'name':'app', 'namespace':'demo'}, 'spec':spec})
    assert 'NEVER_RETURN' not in json.dumps(pod)
    assert pod['scheduling']['omitted_constraints']
    node = normalize('nodes', {'metadata': {'labels': {'workload-tier':'apps', 'secret':'NEVER_RETURN'}}})
    assert node['labels'] == {'workload-tier':'apps'}


@pytest.mark.parametrize('value, expected', [('150m', .15), ('16384Mi', 17179869184), ('1e3',1000), ('5n',5e-9)])
def test_quantities(value, expected):
    assert quantity(value) == expected


@pytest.mark.parametrize('value', ['nan', 'inf', 'garbage', '-1Gi'])
def test_invalid_quantities(value):
    with pytest.raises(ValueError): quantity(value)


def test_effective_init_sidecar_and_overhead_requests():
    p = {'resources':[{'name':'app', 'requests':{'cpu':'1','memory':'1Gi'}},
                      {'name':'sidecar','init':True,'restart_policy':'Always','requests':{'cpu':'500m','memory':'256Mi'}},
                      {'name':'init','init':True,'requests':{'cpu':'2','memory':'2Gi'}}],
         'overhead':{'cpu':'100m','memory':'128Mi'}}
    r = requests(p)
    assert r['cpu'] == 2.6
    assert r['memory'] == quantity('2432Mi')
    assert requests(dict(p, pod_resources_present=True)) is None


def fixture():
    nodes = [normalize('nodes', {'metadata':{'name':'old','labels':{'eks.amazonaws.com/nodegroup':'base','eks.amazonaws.com/capacityType':'ON_DEMAND'}},
                                'status':{'allocatable':{'cpu':'4','memory':'16Gi'}}}),
             normalize('nodes', {'metadata':{'name':'new','labels':{'karpenter.sh/nodepool':'apps','karpenter.sh/capacity-type':'spot'}},
                                'status':{'allocatable':{'cpu':'4','memory':'16Gi'}}})]
    p = normalize('pods', {'metadata':{'name':'db','namespace':'demo','ownerReferences':[{'kind':'StatefulSet','name':'db'}]},
                          'spec':{'nodeName':'old','containers':[{'name':'db','resources':{'requests':{'cpu':'1','memory':'2Gi'}}}]},
                          'status':{'phase':'Running'}})
    return nodes+[p]


def test_migration_and_partial_capacity_are_not_drain_approval():
    result = summarize(fixture(), {'nodes','pods'})
    summary = result[0]
    assert summary['remaining_count'] == 1
    assert summary['placement'][0]['stateful_pods'] == 1
    assert summary['withdrawal_assessment'] == 'not_assessed'
    capacity = next(x for x in result if x.get('name') == 'old')
    assert capacity['resources']['cpu']['requests'] == 1
    assert capacity['resources']['memory']['usage'] is None
    partial = summarize(fixture(), {'nodes'})
    assert not partial[0]['complete']
    assert partial[1]['resources']['cpu']['requests'] is None


def test_conflicting_capacity_labels_are_unknown():
    assert node_group({'labels':{'karpenter.sh/capacity-type':'spot','eks.amazonaws.com/capacityType':'ON_DEMAND'}})['capacity_type']=='unknown'
    assert node_group({'name':'spot-looking-name'})['capacity_type']=='unknown'


def test_argocd_projection_and_rollout_findings():
    app=normalize('applications',{'metadata':{'name':'demo'},'spec':{'source':{'token':'NEVER_RETURN'}},
                                  'status':{'sync':{'status':'OutOfSync'},'health':{'status':'Degraded','message':'NEVER_RETURN'}}})
    assert 'NEVER_RETURN' not in json.dumps(app)
    assert {f['code'] for f in analyze(app)} == {'argocd_application_unhealthy','argocd_application_out_of_sync'}
    r=normalize('rollouts',{'metadata':{'name':'demo'},'spec':{'replicas':2},'status':{'phase':'Degraded','readyReplicas':1}})
    assert analyze(r)[0]['code']=='argo_rollout_not_healthy'


def test_node_profile_never_collects_pods_or_load_balancers(monkeypatch):
    class C:
        region='us-east-1'
        identity={'Account':'000000000000'}
        def check(self): pass
    c=Collector(C(),'test','demo',lambda e:None)
    c.cluster_data={'arn':'arn:aws:eks:us-east-1:000000000000:cluster/demo'}
    c.profile='nodes'
    monkeypatch.setattr('aws_ops_mcp.eks_collect.resolve_bastion',lambda *a:object())
    monkeypatch.setattr('aws_ops_mcp.eks_collect.validate_bastion',lambda *a:None)
    called=[]
    def remote(b,p):
        called.append(p['kind'])
        return {'complete':True,'items':[]}
    c.remote_pages=remote
    c.dependencies=MagicMock()
    c.kubernetes()
    assert set(called)==set(PROFILES['nodes'])
    assert 'pods' not in called
    c.dependencies.assert_not_called()


@pytest.mark.parametrize('code, complete', [('api_not_found',True),('access_denied',False)])
def test_optional_argo_absent_vs_denied(monkeypatch, code, complete):
    class C:
        region='us-east-1'
        identity={'Account':'000000000000'}
        def check(self): pass
    c=Collector(C(),'test','demo',lambda e:None)
    c.cluster_data={'arn':'demo'}
    c.profile='workloads'
    monkeypatch.setattr('aws_ops_mcp.eks_collect.resolve_bastion',lambda *a:object())
    monkeypatch.setattr('aws_ops_mcp.eks_collect.validate_bastion',lambda *a:None)
    c.remote_pages=lambda b,p: {'complete':False,'items':[],'error':code} if p['kind']=='applications' else {'complete':True,'items':[]}
    c.kubernetes()
    assert c.coverage['kubernetes.applications']['complete'] is complete


def test_remote_recipe_compiles_with_new_helpers():
    script=recipe({'kind':'applications'})
    compile(script.split('\n',1)[1].rsplit('\nAWS_OPS_EKS_RECIPE',1)[0],'<recipe>','exec')


def test_profile_validation_before_account_resolution():
    r=Investigations(EvidenceStore()).start('test','us-east-1',['demo'],profile='arbitrary')
    assert r['errors']==[{'code':'profile_invalid'}]


def test_restart_comparison_requires_same_uid():
    from aws_ops_mcp.eks_insights import restart_delta
    old={('demo','app','uid1','c'):2}
    current={('demo','app','uid1','c'):4,('demo','new','uid2','c'):10}
    delta=restart_delta(current,old)
    assert delta['restart_increase']==2
    assert delta['new_or_recreated_containers']==1
    assert restart_delta({('demo','app','uid1','c'):0},old)['counter_resets']==1


def test_large_summary_is_wire_bounded():
    from aws_ops_mcp.contracts import encoded
    items=[]
    for i in range(80):
        items.append(normalize('nodes',{'metadata':{'name':str(i),'labels':{'eks.amazonaws.com/nodegroup':str(i)+'x'*200,'eks.amazonaws.com/capacityType':'ON_DEMAND'}},'status':{'allocatable':{'cpu':'4','memory':'16Gi'}}}))
    s=summarize(items,{'nodes','pods'})[0]
    assert s['placement_truncated']
    assert len(encoded(s))<12000


def test_ec2_capacity_fallback_and_conflict():
    assert node_group({'labels':{},'ec2_capacity_type':'spot'})['capacity_type']=='spot'
    assert node_group({'labels':{'eks.amazonaws.com/capacityType':'ON_DEMAND'},'ec2_capacity_type':'spot'})['capacity_type']=='unknown'
