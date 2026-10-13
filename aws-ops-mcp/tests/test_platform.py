import json
import threading
import time
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock

import pytest
import botocore.session
from botocore.exceptions import ClientError
from botocore.validate import validate_parameters

from aws_ops_mcp.config import Account
from aws_ops_mcp.costs import validate
from aws_ops_mcp.evidence import EvidenceStore
from aws_ops_mcp.eks_cli import CollectionError
from aws_ops_mcp.ops_runtime import ReadContext
from aws_ops_mcp.platform_ops import Platform, OperationsJobs
from aws_ops_mcp.aws import AccountMismatch

ACCOUNT = '000000000001'
ROOT = 'r-abcd'
OU = 'ou-abcd-abcdefgh'
DATES = dict(start_date='2026-01-01', end_date='2026-02-01')


@pytest.fixture(autouse=True)
def aliases(monkeypatch):
    monkeypatch.setattr('aws_ops_mcp.ops_runtime.resolve', lambda alias, region: Account(
        account_id=ACCOUNT if alias == 'one' else '000000000002', regions=[region]))
    monkeypatch.delenv('AWS_OPS_AUDIT_FILE', raising=False)


class APIs:
    def __init__(self):
        self.calls = []
        self.deny_policy = False
        self.cost_mode = 'normal'
        self.cycle = False

    def __getattribute__(self, name):
        attr = object.__getattribute__(self, name)
        if name.startswith(('list_', 'describe_', 'get_cost_')):
            def invoke(**params):
                self.calls.append((name, params.copy()))
                return attr(**params)
            return invoke
        return attr

    def describe_organization(self):
        return {'Organization': {'Id':'o-abcdefghij', 'FeatureSet':'ALL', 'MasterAccountId':ACCOUNT,
                                 'MasterAccountEmail':'do-not-return@example.test'}}

    def list_accounts(self, **params):
        if not params.get('NextToken'):
            return {'Accounts': [], 'NextToken':'empty-page'}
        return {'Accounts':[{'Id':ACCOUNT, 'Name':'demo', 'State':'ACTIVE',
                             'Email':'secret@example.test'}]}

    def list_roots(self, **params):
        return {'Roots':[{'Id':ROOT, 'Name':'Root', 'PolicyTypes':[{'Type':kind, 'Status':'ENABLED'}
                        for kind in ('SERVICE_CONTROL_POLICY','RESOURCE_CONTROL_POLICY')]}]}

    def list_organizational_units_for_parent(self, **params):
        if self.cycle:
            return {'OrganizationalUnits':[{'Id':OU, 'Name':'Loop'}]}
        return {'OrganizationalUnits':[{'Id':OU, 'Name':'Demo'}] if params['ParentId']==ROOT else []}

    def list_children(self, **params):
        return {'Children':[{'Id':ACCOUNT, 'Type':'ACCOUNT'}] if params['ParentId']==OU else []}

    def list_policies_for_target(self, **params):
        if self.deny_policy and params['Filter']=='RESOURCE_CONTROL_POLICY':
            raise ClientError({'Error':{'Code':'AccessDeniedException', 'Message':'SECRET'}}, 'ListPoliciesForTarget')
        return {'Policies':[{'Id':'p-abcdefgh', 'Name':'Baseline', 'AwsManaged':False}]
                if params['TargetId']==ROOT and params['Filter']=='SERVICE_CONTROL_POLICY' else []}

    def get_cost_and_usage(self, **params):
        if self.cost_mode=='deny':
            raise ClientError({'Error':{'Code':'AccessDeniedException', 'Message':'SECRET'}}, 'GetCostAndUsage')
        metric=params['Metrics'][0]
        if self.cost_mode=='empty':
            return {'ResultsByTime':[]}
        groups=[{'Keys':['EC2'], 'Metrics':{metric:{'Amount':'0.1', 'Unit':'USD'}}},
                {'Keys':['S3'], 'Metrics':{metric:{'Amount':'0.2', 'Unit':'USD'}}},
                {'Keys':['Credit'], 'Metrics':{metric:{'Amount':'-0.05', 'Unit':'EUR'}}}]
        if self.cost_mode=='invalid':
            groups[0]['Metrics'][metric]['Amount']='NaN'
        result={'ResultsByTime':[{'TimePeriod':params['TimePeriod'], 'Estimated':True, 'Groups':groups}]}
        if self.cost_mode=='cycle':
            result['NextPageToken']='repeat'
        return result


def make(api, factory=None, clock=time.monotonic):
    session=MagicMock()
    session.client.return_value=api
    platform=Platform(EvidenceStore(), factory=factory or (lambda *a:(session,None)), clock=clock)
    return platform,session


def details(platform, result):
    return platform.store.get(result['evidence_id'])['items']


def test_organization_tree_empty_page_and_inheritance_without_emails():
    api=APIs();platform,_=make(api)
    result=platform.query('one','us-east-1','organization')
    assert result['status']=='ok' and result['account_id']==ACCOUNT
    rows=details(platform,result)
    account=next(r for r in rows if r['kind']=='organization_account')
    assert account['ancestor_ids']==[OU,ROOT]
    assert account['policy_ids_by_level'][-1]['scp_ids']==['p-abcdefgh']
    assert account['policy_inheritance_observed'] and account['scp_applies'] is False
    assert result['summary']['observed_accounts']==1
    assert 'Email' not in json.dumps(rows) and '@example.test' not in json.dumps(result)
    assert all(name.startswith(('list_', 'describe_')) for name,_ in api.calls)


def test_policy_access_denied_is_unknown_not_empty_or_healthy():
    api=APIs();api.deny_policy=True;platform,_=make(api)
    result=platform.query('one','us-east-1','organization')
    assert result['status']=='partial' and not result['coverage']['complete']
    assert any(e['code']=='access_denied' for e in result['errors'])
    row=next(r for r in details(platform,result) if r['kind']=='organization_account')
    assert not row['policy_inheritance_observed']
    assert row['policy_ids_by_level'][0]['rcp_ids'] is None
    assert 'SECRET' not in json.dumps(result)


def test_inventory_only_explicitly_excludes_policy_evaluation():
    api=APIs();platform,_=make(api)
    result=platform.query('one','us-west-2','organization',include_policies=False)
    assert result['status']=='ok'
    assert not any(n=='list_policies_for_target' for n,_ in api.calls)
    assert not next(r for r in details(platform,result) if r['kind']=='organization_account')['policy_inheritance_observed']


def test_tree_cycle_preserves_partial_evidence():
    api=APIs();api.cycle=True;platform,_=make(api)
    result=platform.query('one','us-east-1','organization')
    assert result['status']=='partial'
    assert result['errors'][0]['code']=='organization_tree_cycle'
    assert result.get('evidence_id')


def test_cost_decimal_negative_currency_estimated_and_account_filter():
    api=APIs();platform,session=make(api)
    result=platform.query('one','eu-west-1','cost',**DATES)
    assert result['status']=='ok'
    assert result['summary']['totals_by_currency']=={'USD':'0.3','EUR':'-0.05'}
    assert result['summary']['estimated'] and not result['summary']['savings_verified']
    params=api.calls[0][1]
    assert params['Filter']['Dimensions']=={'Key':'LINKED_ACCOUNT','Values':[ACCOUNT]}
    session.client.assert_called_once_with('ce',region_name='us-east-1',config=None)


def test_payer_scope_is_explicit_usage_region_separate():
    api=APIs();platform,_=make(api)
    result=platform.query('one','us-east-1','cost',**DATES,organization_scope=True,usage_region='eu-west-1')
    assert result['summary']['billing_scope']=='caller_visible_billing_view'
    assert api.calls[0][1]['Filter']=={'Dimensions':{'Key':'REGION','Values':['eu-west-1']}}
    api.calls=[]
    platform.query('one','us-east-1','cost',**DATES,usage_region='eu-west-1')
    assert len(api.calls[0][1]['Filter']['And'])==2


@pytest.mark.parametrize('mode,code', [('deny','access_denied'),('invalid','invalid_cost_amount'),('cycle','duplicate_cost_group')])
def test_cost_failure_never_validates_aggregate(mode,code):
    api=APIs();api.cost_mode=mode;platform,_=make(api)
    result=platform.query('one','us-east-1','cost',**DATES)
    assert result['status'] in {'partial','error'} and not result['coverage']['complete']
    assert not result['summary'].get('aggregate_totals_verified',False)
    assert result['errors'][0]['code']==code
    assert 'SECRET' not in json.dumps(result)


def test_empty_cost_data_not_zero_spend_claim():
    api=APIs();api.cost_mode='empty';platform,_=make(api)
    result=platform.query('one','us-east-1','cost',**DATES)
    assert result['status']=='partial'
    assert result['summary']['assessment']=='no_cost_groups_returned'
    assert not result['summary']['aggregate_totals_verified']


@pytest.mark.parametrize('left,right', [('2026-02-30','2026-03-01'),('2026-01-01','2026-01-01'),('2024-01-01','2026-01-01'),('2026-1-1','2026-02-01')])
def test_dates_rejected_before_authentication(left,right):
    factory=MagicMock();platform,_=make(APIs(),factory=factory)
    result=platform.query('one','us-east-1','cost',start_date=left,end_date=right)
    assert result['status']=='error' and not result['coverage']['complete']
    factory.assert_not_called()


def test_future_dates_and_unsupported_metric():
    tomorrow=(datetime.now(timezone.utc)+timedelta(days=1)).date().isoformat()
    with pytest.raises(CollectionError):validate('2026-01-01',tomorrow,'UnblendedCost','MONTHLY')
    with pytest.raises(CollectionError):validate('2026-01-01','2026-02-01','UsageQuantity','MONTHLY')


def test_runtime_allowlist_deadline_clients_pages_empty_and_cycle():
    api=APIs();platform,session=make(api)
    clock=[0];context=ReadContext('one','us-east-1',platform.factory,lambda:clock[0])
    with pytest.raises(CollectionError,match='operation_not_permitted'):context.call('organizations','delete_organization')
    assert len(list(context.pages('organizations','list_accounts','Accounts')))==1
    session.client.assert_called_once()
    context.clients['organizations'].list_accounts=lambda **p:{'Accounts':[], 'NextToken':'same'}
    with pytest.raises(CollectionError,match='pagination_cycle'):list(context.pages('organizations','list_accounts','Accounts'))
    clock[0]=61
    with pytest.raises(CollectionError,match='deadline_exceeded'):context.call('organizations','list_accounts')


def test_runtime_limits_and_partition():
    platform,_=make(APIs());context=ReadContext('one','us-east-1',platform.factory)
    context.calls=200
    with pytest.raises(CollectionError,match='api_call_limit'):context.call('organizations','list_roots')
    with pytest.raises(CollectionError,match='partition_not_supported'):ReadContext('one','cn-north-1',platform.factory)


def test_audit_metadata_no_parameters_and_failure_visible(tmp_path,monkeypatch):
    audit=tmp_path/'audit.jsonl';monkeypatch.setenv('AWS_OPS_AUDIT_FILE',str(audit))
    api=APIs();platform,_=make(api)
    result=platform.query('one','us-east-1','cost',**DATES)
    rows=[json.loads(r) for r in audit.read_text().splitlines()]
    assert rows[0]['account_id']==ACCOUNT and 'start_date' not in audit.read_text()
    assert 'Filter' not in audit.read_text() and result['coverage']['audit_recorded']
    monkeypatch.setenv('AWS_OPS_AUDIT_FILE',str(tmp_path/'missing'/'audit'))
    failed=platform.query('one','us-east-1','cost',**DATES)
    assert failed['status']=='partial' and failed['errors'][0]['code']=='audit_unavailable'


@pytest.mark.parametrize('code,expected',[('ExpiredToken','authentication_expired_or_invalid'),('ThrottlingException','throttled')])
def test_authentication_errors_sanitized(code,expected):
    def factory(*args):raise ClientError({'Error':{'Code':code,'Message':'TOKEN_SECRET'}},'GetCallerIdentity')
    platform,_=make(APIs(),factory=factory)
    result=platform.query('one','us-east-1','organization')
    assert result['status']=='error' and result['errors'][0]['code']==expected
    assert 'TOKEN_SECRET' not in json.dumps(result)


def test_multi_scope_partial_isolation_and_no_summed_money():
    def factory(config,region):
        if config.account_id!='000000000001':
            raise ClientError({'Error':{'Code':'AccessDenied','Message':'secret'}},'GetCallerIdentity')
        session=MagicMock();session.client.return_value=APIs();return session,None
    platform,_=make(APIs(),factory=factory);jobs=OperationsJobs(platform)
    response=jobs.start([{'account':'one','region':'us-east-1'},{'account':'two','region':'eu-west-1'}],'cost',**DATES)
    identifier=response['investigation_id']
    for _ in range(100):
        result=jobs.get(identifier)
        if result['summary']['state']=='finished':break
        time.sleep(.01)
    assert result['summary']['state']=='finished' and result['status']=='partial'
    assert len(result['items'])==2
    assert result['items'][0]['account_id']==ACCOUNT
    assert result['items'][1]['errors'][0]['code']=='access_denied'
    assert not result['summary']['cross_scope_money_totals_aggregated']
    assert result['items'][0]['evidence_id']
    assert jobs.start([{'account':'one','region':'us-east-1'},{'account':'one','region':'eu-west-1'}],'organization')['status']=='error'


def test_jobs_capacity_concurrency_and_ttl():
    entered=threading.Event();release=threading.Event();active=[0];maximum=[0];lock=threading.Lock()
    class Slow:
        def query(self,account,region,analysis,**params):
            with lock:active[0]+=1;maximum[0]=max(maximum[0],active[0])
            entered.set();release.wait(2)
            with lock:active[0]-=1
            return {'status':'ok','coverage':{'complete':True},'summary':{},'account':account,'region':region}
    clock=[0];jobs=OperationsJobs(Slow(),clock=lambda:clock[0])
    scopes=[{'account':str(i),'region':'us-east-1'} for i in range(4)]
    first=jobs.start(scopes,'organization');entered.wait(1)
    second=jobs.start([scopes[0]],'organization')
    assert jobs.start([scopes[0]],'organization')['errors'][0]['code']=='operations_capacity_reached'
    release.set()
    for _ in range(100):
        if jobs.get(first['investigation_id'])['summary']['state']=='finished' and jobs.get(second['investigation_id'])['summary']['state']=='finished':break
        time.sleep(.01)
    assert maximum[0]<=3 # two scopes in first job, one in second
    clock[0]=901
    assert jobs.get(first['investigation_id'])['errors'][0]['code']=='operations_missing_or_expired'


def test_sdk_parameter_contracts():
    session=botocore.session.get_session()
    models={s:session.get_service_model(s) for s in ('organizations','ce')}
    calls=[('organizations','DescribeOrganization',{}),('organizations','ListAccounts',{}),
           ('organizations','ListRoots',{}),('organizations','ListOrganizationalUnitsForParent',{'ParentId':ROOT}),
           ('organizations','ListChildren',{'ParentId':OU,'ChildType':'ACCOUNT'}),
           ('organizations','ListPoliciesForTarget',{'TargetId':ACCOUNT,'Filter':'RESOURCE_CONTROL_POLICY'}),
           ('ce','GetCostAndUsage',{'TimePeriod':{'Start':'2026-01-01','End':'2026-02-01'},'Granularity':'MONTHLY',
             'Metrics':['UnblendedCost'],'GroupBy':[{'Type':'DIMENSION','Key':'SERVICE'}],
             'Filter':{'Dimensions':{'Key':'LINKED_ACCOUNT','Values':[ACCOUNT]}}})]
    for service,name,params in calls:
        shape=models[service].operation_model(name).input_shape
        if shape is not None:validate_parameters(params,shape)
        else:assert not params


def test_disabled_policy_types_are_observed_without_denied_extra_calls():
    api=APIs()
    api.list_roots=lambda **p:{'Roots':[{'Id':ROOT,'Name':'Root','PolicyTypes':[]}]}
    platform,_=make(api)
    result=platform.query('one','us-east-1','organization')
    assert result['status']=='ok' and result['summary']['enabled_policy_types']==[]
    assert not any(n=='list_policies_for_target' for n,_ in api.calls)


def test_transitioning_policy_type_is_unknown_and_partial():
    api=APIs()
    api.list_roots=lambda **p:{'Roots':[{'Id':ROOT,'Name':'Root','PolicyTypes':[
        {'Type':'SERVICE_CONTROL_POLICY','Status':'PENDING_ENABLE'}]}]}
    platform,_=make(api);result=platform.query('one','us-east-1','organization')
    assert result['status']=='partial' and result['errors'][0]['code']=='policy_type_transitioning'
    row=next(r for r in details(platform,result) if r['kind']=='organization_account')
    assert row['policy_ids_by_level'][0]['scp_ids'] is None
    assert not row['policy_inheritance_observed']


def test_unknown_account_parent_is_partial():
    api=APIs();api.list_children=lambda **p:{'Children':[]}
    platform,_=make(api);result=platform.query('one','us-east-1','organization')
    assert result['status']=='partial'
    assert result['errors'][0]['code']=='account_parent_unobserved'
    row=next(r for r in details(platform,result) if r['kind']=='organization_account')
    assert not row['policy_inheritance_observed']


def test_call_bounds_object_limit_page_limit_and_source_capture():
    api=APIs();platform,_=make(api);context=ReadContext('one','us-east-1',platform.factory)
    api.list_accounts=lambda **p:{'Accounts':[{}]*1001}
    iterator=context.pages('organizations','list_accounts','Accounts')
    with pytest.raises(CollectionError,match='object_limit'):list(iterator)
    assert context.calls==1 and context.sources[0]['operation']=='list_accounts'
    index=[0]
    def page(**p):index[0]+=1;return {'Accounts':[],'NextToken':str(index[0])}
    api.list_accounts=page
    with pytest.raises(CollectionError,match='page_limit'):list(context.pages('organizations','list_accounts','Accounts'))


def test_account_mismatch_blocks_all_service_calls():
    api=APIs()
    def factory(*args):raise AccountMismatch()
    platform,_=make(api,factory=factory)
    result=platform.query('one','us-east-1','cost',**DATES)
    assert result['status']=='error' and result['errors'][0]['code']=='account_mismatch'
    assert not api.calls


@pytest.mark.parametrize('code,expected',[('ResourceNotFoundException','resource_not_found'),
                                         ('AWSOrganizationsNotInUseException','organization_not_in_use'),
                                         ('DataUnavailableException','cost_data_unavailable')])
def test_specific_service_errors_retained_without_message(code,expected):
    api=APIs()
    def fail(**p):raise ClientError({'Error':{'Code':code,'Message':'DO_NOT_LOG'}},'GetCostAndUsage')
    api.get_cost_and_usage=fail
    platform,_=make(api);result=platform.query('one','us-east-1','cost',**DATES)
    assert result['errors'][0]['code']==expected and 'DO_NOT_LOG' not in json.dumps(result)


def test_queries_are_fresh_and_evidence_survives_output_truncation():
    api=APIs();platform,_=make(api)
    api.list_accounts=lambda **p:{'Accounts':[{'Id':str(i).zfill(12),'Name':'demo','State':'ACTIVE'} for i in range(40)]}
    result=platform.query('one','us-east-1','organization',include_policies=False)
    assert result['coverage']['output_truncated']
    saved=platform.store.get(result['evidence_id'])
    assert saved['summary']['available_items']>len(result['items'])
    before=len(api.calls)
    platform.query('one','us-east-1','organization',include_policies=False)
    assert len(api.calls)>before and result['coverage']['fresh'] and result['coverage']['cache_age_seconds']==0


def test_evidence_unavailable_and_wire_budget_do_not_claim_complete():
    api=APIs();platform,_=make(api);platform.store=EvidenceStore(max_bytes=1)
    result=platform.query('one','us-east-1','cost',**DATES)
    assert result['status']=='partial' and not result['coverage']['complete']
    assert any(e['code']=='evidence_unavailable' for e in result['errors'])
    assert len(json.dumps(result).encode())<=12288


def test_region_configuration_is_enforced(monkeypatch):
    from aws_ops_mcp.config import ConfigurationError
    def refuse(*args):raise ConfigurationError()
    monkeypatch.setattr('aws_ops_mcp.ops_runtime.resolve',refuse)
    factory=MagicMock();platform,_=make(APIs(),factory=factory)
    result=platform.query('one','eu-west-1','organization')
    assert result['errors'][0]['code']=='configuration_invalid'
    factory.assert_not_called()


def test_precision_and_disabled_audit_are_explicit():
    api=APIs()
    def exact(**params):
        return {'ResultsByTime':[{'TimePeriod':params['TimePeriod'],'Estimated':False,'Groups':[
            {'Keys':[name],'Metrics':{params['Metrics'][0]:{'Amount':amount,'Unit':'USD'}}}
            for name,amount in [('A','123456789012345678901234.123456789012345678'),('B','0.000000000000000001')]]}]}
    api.get_cost_and_usage=exact
    platform,_=make(api);result=platform.query('one','us-east-1','cost',**DATES)
    assert result['summary']['totals_by_currency']['USD']=='123456789012345678901234.123456789012345679'
    assert not result['coverage']['audit_enabled'] and not result['coverage']['audit_recorded']


def test_cost_group_bound_keeps_evidence_without_verified_totals():
    api=APIs()
    def many(**params):
        return {'ResultsByTime':[{'TimePeriod':params['TimePeriod'],'Estimated':False,'Groups':[
            {'Keys':[str(i)],'Metrics':{params['Metrics'][0]:{'Amount':'1','Unit':'USD'}}} for i in range(1001)]}]}
    api.get_cost_and_usage=many
    platform,_=make(api);result=platform.query('one','us-east-1','cost',**DATES)
    assert result['status']=='partial' and result['errors'][0]['code']=='cost_group_limit'
    assert not result['summary']['aggregate_totals_verified'] and result.get('evidence_id')
