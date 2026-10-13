from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock
import json
import threading

import pytest
from botocore.exceptions import ClientError
from aws_ops_mcp.eks_readiness import assess, node_matches, selector_match
from aws_ops_mcp.eks_history import snapshot, compare
from aws_ops_mcp.eks_operations import EKSOperations, tcp_matches, sg_ingress
from aws_ops_mcp.eks_kubernetes import normalize
from aws_ops_mcp.evidence import EvidenceStore

SG1='sg-00000000000000001'; SG2='sg-00000000000000002'; VPC='vpc-00000000'
KINDS={'nodes','pods','replicasets','deployments','statefulsets','poddisruptionbudgets','persistentvolumeclaims','persistentvolumes'}


def fixtures():
    rows=[]
    for name,cap in [('old','ON_DEMAND'),('new','SPOT')]:
        rows.append(normalize('nodes',{'metadata':{'name':name,'labels':{'eks.amazonaws.com/capacityType':cap,'topology.kubernetes.io/zone':'us-east-1a'}},
             'status':{'conditions':[{'type':'Ready','status':'True'}],'allocatable':{'cpu':'4','memory':'8Gi'}}}))
    rows.append(normalize('pods',{'metadata':{'name':'app-0','namespace':'demo','uid':'uid','labels':{'app':'demo'},'ownerReferences':[{'kind':'StatefulSet','name':'app'}]},
         'spec':{'nodeName':'old','containers':[{'name':'app','resources':{'requests':{'cpu':'1','memory':'1Gi'}}}]},
         'status':{'phase':'Running','conditions':[{'type':'Ready','status':'True'}],'containerStatuses':[{'name':'app','restartCount':1,'ready':True}]}}))
    rows.append(normalize('statefulsets',{'metadata':{'name':'app','namespace':'demo'},'spec':{'replicas':2}}))
    return rows


def test_withdrawal_no_positive_drain_authorization():
    r=assess(fixtures(),KINDS)
    assert not r[0]['drain_authorized']
    w=next(x for x in r if x['kind']=='withdrawal_workload')
    assert w['candidate_nodes']==['new']
    assert w['assessment']=='requires_review'
    assert not assess(fixtures(),{'nodes','pods'})[0]['complete']


def test_pdb_blocks_and_omitted_selector_is_gap():
    items=fixtures()
    pdb=normalize('poddisruptionbudgets',{'metadata':{'name':'app','namespace':'demo','generation':1},
        'spec':{'selector':{'matchLabels':{'app':'demo'}}},'status':{'observedGeneration':1,'disruptionsAllowed':0}})
    r=assess(items+[pdb],KINDS)
    assert 'pdb_blocks_eviction' in r[2]['blockers']
    pdb['selector']['omitted']=True
    assert 'pdb_selector_omitted' in assess(items+[pdb],KINDS)[2]['gaps']


def test_volume_az_and_local_storage_blockers():
    rows=fixtures();pod=next(x for x in rows if x['kind']=='pods');pod['volumes']=['data'];pod['local_storage']=True
    rows.append(normalize('persistentvolumeclaims',{'metadata':{'name':'data','namespace':'demo'},'spec':{'volumeName':'pv'},'status':{'phase':'Bound'}}))
    rows.append(normalize('persistentvolumes',{'metadata':{'name':'pv'},'spec':{'csi':{'driver':'ebs.csi.aws.com'},'nodeAffinity':{'required':{'nodeSelectorTerms':[{'matchExpressions':[{'key':'topology.kubernetes.io/zone','operator':'In','values':['us-east-1b']}]}]}}}}))
    r=assess(rows,KINDS)[2]
    assert 'local_storage_requires_review' in r['blockers']
    assert 'no_existing_spot_node_matches' in r['blockers']


def test_affinity_and_taint_are_not_ignored():
    n={'labels':{},'taints':[{'key':'workload-tier','value':'apps','effect':'NoSchedule'}]}
    assert node_matches({},n) is False
    assert node_matches({'tolerations':[{'key':'workload-tier','operator':'Equal','value':'apps'}]},n) is True
    assert node_matches({'omitted_constraints':True},n) is None
    assert selector_match({'match_expressions':[{'key':'app','operator':'DoesNotExist'}]},{'app':'demo'}) is False


def test_spot_singleton_and_colocation_risks():
    rows=fixtures();p=next(x for x in rows if x['kind']=='pods');p['node']='new';p['owners']=[{'kind':'StatefulSet','name':'argocd-controller'}]
    risks=[r for r in assess(rows,KINDS) if r['kind']=='spot_workload_risk']
    assert 'single_observed_replica' in risks[0]['risks']
    assert 'management_component_on_spot_name_based' in risks[0]['risks']


def test_history_detects_real_deltas_not_recreated_pods():
    old=snapshot(fixtures())
    rows=fixtures();p=next(x for x in rows if x['kind']=='pods');p['containers'][0].update(restarts=3,last_terminated='OOMKilled',last_finished_at='2026-01-01T01:00:00Z')
    now=snapshot(rows)
    r=compare(now,old)
    assert r['restarts']['restart_increase']==2
    assert r['container_changes'][0]['code']=='new_oom_termination'
    p['uid']='new-uid'
    r=compare(snapshot(rows),old)
    assert r['restarts']['restart_increase']==0
    assert not r['container_changes']


def test_history_first_warning_is_only_first_observed():
    old=snapshot([])
    current=snapshot([{'kind':'events','namespace':'demo','name':'ev','type':'Warning','reason':'Unhealthy','count':7}])
    r=compare(current,old)
    assert r['warning_changes'][0]['interpretation']=='first_observed'


def service(client):
    session=MagicMock();session.client.return_value=client
    return EKSOperations(EvidenceStore(),factory=lambda *a:(session,None))


def domain_client(allow=False):
    client=MagicMock()
    client.describe_domain.return_value={'DomainStatus':{'VPCOptions':{'VpcId':VPC,'SecurityGroupIds':[SG2]},'Endpoints':{'vpc':'domain.example'}}}
    ingress=[{'IpProtocol':'tcp','FromPort':443,'ToPort':443,'UserIdGroupPairs':[{'GroupId':SG1}]}] if allow else []
    client.describe_security_groups.return_value={'SecurityGroups':[{'GroupId':SG1,'VpcId':VPC,'IpPermissionsEgress':[{'IpProtocol':'-1','IpRanges':[{'CidrIp':'0.0.0.0/0'}]}]},
          {'GroupId':SG2,'VpcId':VPC,'IpPermissions':ingress}]}
    return client


@pytest.mark.parametrize('allow,expected',[(False,'missing_ingress_rule'),(True,'sg_rule_observed')])
def test_network_rule_read_only(configured,allow,expected):
    c=domain_client(allow)
    r=service(c).query('test','us-east-1','network',source_security_group_ids=[SG1],destination_kind='opensearch',destination_name='demo')
    assert r['items'][0]['assessment']==expected
    assert r['items'][0]['egress_assessment']=='rule_observed'
    assert not r['coverage']['connection_verified']
    assert all(not any(w in name for w in ('authorize','modify','delete')) for name,_,_ in c.mock_calls)


def test_network_cidr_without_source_ip_is_unknown():
    groups=[{'GroupId':SG2,'IpPermissions':[{'IpProtocol':'tcp','FromPort':443,'ToPort':443,'IpRanges':[{'CidrIp':'10.0.0.0/8'}]}]}]
    assert sg_ingress(groups,SG1,443)==([],True)
    assert sg_ingress(groups,SG1,443,'10.1.1.1')[0]
    assert not tcp_matches({'IpProtocol':'udp','FromPort':443,'ToPort':443},443)


def test_network_source_attachment_is_verified_separately(configured):
    c=domain_client(True)
    c.describe_network_interfaces.return_value={'NetworkInterfaces':[]}
    r=service(c).query('test','us-east-1','network',source_security_group_ids=[SG1],source_private_ip='10.1.1.1',destination_kind='opensearch',destination_name='demo')
    assert r['items'][0]['source_sg_attached_to_ip'] is False
    assert not r['coverage']['connection_verified']


def metric_client(hours=24,status='Complete',samples=None):
    c=MagicMock();end=datetime.now(timezone.utc).replace(minute=0,second=0,microsecond=0)
    stamps=[end-timedelta(hours=i+1) for i in range(samples if samples is not None else hours)]
    c.get_metric_data.return_value={'MetricDataResults':[{'Id':k,'StatusCode':status,'Timestamps':stamps,'Values':[100 if k=='cpu' else 104857600]*len(stamps)} for k in ('cpu','memory')]}
    return c


def test_historical_rightsizing_has_coverage_and_no_autoapply(configured):
    c=metric_client()
    r=service(c).query('test','us-east-1','rightsizing',cluster='demo',namespace='demo',pod_name='app',hours=24,cpu_request='500m',memory_request='256Mi')
    assert r['coverage']['complete']
    assert r['items'][0]['request_reference']==500
    assert r['items'][0]['candidate_request_with_30_percent_margin']==130
    assert not r['items'][0]['apply_recommendation']
    assert c.get_metric_data.call_args.kwargs['MetricDataQueries'][0]['MetricStat']['Stat']=='Maximum'


@pytest.mark.parametrize('status,samples',[('PartialData',24),('Complete',2),('Complete',0)])
def test_sparse_partial_missing_history_never_recommends(configured,status,samples):
    r=service(metric_client(status=status,samples=samples)).query('test','us-east-1','rightsizing',cluster='demo',namespace='demo',pod_name='app',hours=24,cpu_request='500m',memory_request='256Mi')
    assert r['status'] in {'partial','error'}
    assert not r['coverage']['complete']
    assert all(i['candidate_request_with_30_percent_margin'] is None for i in r['items'])


def test_metric_pagination_cycle_and_safe_errors(configured):
    c=metric_client();c.get_metric_data.return_value['NextToken']='repeat'
    r=service(c).query('test','us-east-1','rightsizing',cluster='demo',namespace='demo',pod_name='app',hours=24)
    assert r['errors'][0]['code']=='metric_pagination_cycle'
    c=domain_client();c.describe_domain.side_effect=ClientError({'Error':{'Code':'AccessDeniedException','Message':'NEVER_RETURN'}},'DescribeDomain')
    r=service(c).query('test','us-east-1','network',source_security_group_ids=[SG1],destination_kind='opensearch',destination_name='demo')
    assert 'NEVER_RETURN' not in json.dumps(r)
    assert r['errors'][0]['code']=='access_denied'


def test_invalid_target_before_aws(configured):
    c=MagicMock()
    r=service(c).query('test','us-east-1','network',source_security_group_ids=['bad'],destination_kind='opensearch',destination_name='demo')
    assert r['errors'][0]['code']=='invalid_source_security_groups'
    c.describe_domain.assert_not_called()
    r=service(c).query('test','us-east-1','rightsizing',cluster='demo',namespace='demo',pod_name='app',hours=500)
    assert r['errors'][0]['code']=='historical_window_24_to_336_hours'


def test_botocore_api_parameter_contracts(configured):
    import botocore.session
    from botocore.validate import validate_parameters
    models=botocore.session.get_session()
    c=domain_client(True)
    r=service(c).query('test','us-east-1','network',source_security_group_ids=[SG1],source_private_ip='10.1.1.1',destination_kind='opensearch',destination_name='demo')
    for api,method,modelname in [('opensearch','describe_domain','DescribeDomain'),('ec2','describe_security_groups','DescribeSecurityGroups'),('ec2','describe_network_interfaces','DescribeNetworkInterfaces')]:
        args=getattr(c,method).call_args.kwargs
        validate_parameters(args,models.get_service_model(api).operation_model(modelname).input_shape)
    c=metric_client()
    service(c).query('test','us-east-1','rightsizing',cluster='demo',namespace='demo',pod_name='app',hours=24)
    validate_parameters(c.get_metric_data.call_args.kwargs,models.get_service_model('cloudwatch').operation_model('GetMetricData').input_shape)


def test_redis_nondefault_port_and_sg(configured):
    c=domain_client(True)
    c.describe_cache_clusters.return_value={'CacheClusters':[{'CacheSubnetGroupName':'subnets','SecurityGroups':[{'SecurityGroupId':SG2}],'CacheNodes':[{'Endpoint':{'Address':'redis.example','Port':6380}}]}]}
    c.describe_cache_subnet_groups.return_value={'CacheSubnetGroups':[{'VpcId':VPC}]}
    r=service(c).query('test','us-east-1','network',source_security_group_ids=[SG1],destination_kind='redis',destination_name='demo-001')
    assert r['summary']['port']==6380
    assert r['items'][0]['assessment']=='missing_ingress_rule'


def test_oversized_history_projection_is_bounded():
    from aws_ops_mcp.contracts import encoded
    old=snapshot([])
    current=snapshot([{'kind':'nodes','name':str(i)+'x'*250,'conditions':[]} for i in range(100)])
    r=compare(current,old)
    assert len(encoded(r))<12000 and r['output_truncated']


def test_history_manager_isolation_partial_baselines_and_ttl(monkeypatch):
    import time
    from aws_ops_mcp.config import Account
    from aws_ops_mcp.eks_collect import Collector
    from aws_ops_mcp.eks_jobs import Investigations
    monkeypatch.setattr('aws_ops_mcp.eks_jobs.resolve',lambda *a:Account(account_id='000000000000',regions=['us-east-1']))
    current=[1];partial=[False];now=[0]
    class CLI:
        def __init__(self,*a,**kw): self.identity={'Account':'000000000000','Arn':'example'}
        def check(self): pass
    class C(Collector):
        def aws(self): self.record('aws.cluster',[])
        def kubernetes(self,*a):
            items=fixtures()
            p=next(x for x in items if x['kind']=='pods');p['containers'][0]['restarts']=current[0]
            self.record('kubernetes.nodes',[x for x in items if x['kind']=='nodes'])
            self.record('kubernetes.pods',[p],complete=not partial[0])
            self.record('kubernetes.events',[])
    store=EvidenceStore();manager=Investigations(store,cli_factory=CLI,collector_factory=C,clock=lambda:now[0])
    def run(alias='test'):
        r=manager.start(alias,'us-east-1',['demo']);key=r['investigation_id']
        for _ in range(100):
            r=manager.get(key)
            if r['summary']['state']=='finished': break
            time.sleep(.01)
        assert r['summary']['state']=='finished'
        views=[i for i in store.get(r['evidence_id'])['items'] if i.get('kind')=='health_comparison']
        return views
    assert run()[0]['baseline_available'] is False
    current[0]=3
    assert run()[0]['restarts']['restart_increase']==2
    assert run('other')[0]['baseline_available'] is False
    partial[0]=True;current[0]=9
    assert run()==[]
    partial[0]=False;current[0]=5
    assert run()[0]['restarts']['restart_increase']==2
    now[0]=90000
    assert run()[0]['baseline_available'] is False
