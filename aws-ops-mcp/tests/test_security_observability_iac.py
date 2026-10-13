import json
from datetime import datetime,timezone,timedelta
from unittest.mock import MagicMock
import pytest
import botocore.session
from botocore.exceptions import ClientError
from botocore.validate import validate_parameters
from aws_ops_mcp.platform_ops import Platform
from aws_ops_mcp.evidence import EvidenceStore
from aws_ops_mcp.terraform_plan import query as plan_query

ACCOUNT='000000000000';DETECTOR='0'*32;FINDING='1'*32
NOW=datetime.now(timezone.utc)-timedelta(minutes=1)
WINDOW={'start_time':(NOW-timedelta(hours=1)).isoformat(),'end_time':NOW.isoformat()}


class APIs:
    def __init__(self):self.deny=False;self.foreign=False;self.detectors=True;self.disabled=False;self.calls=[]
    def list_detectors(self,**p):return {'DetectorIds':[DETECTOR] if self.detectors else []}
    def get_detector(self,**p):return {'Status':'DISABLED' if self.disabled else 'ENABLED'}
    def list_findings(self,**p):self.calls.append(('guardduty','ListFindings',p));return {'FindingIds':[FINDING]}
    def get_findings(self,**p):
        if 'DetectorId' in p:return {'Findings':[{'Id':FINDING,'Arn':'arn:aws:guardduty:us-east-1:'+ACCOUNT+':detector/'+DETECTOR+'/finding/'+FINDING,
            'AccountId':ACCOUNT if not self.foreign else '000000000001','Region':'us-east-1','Type':'Recon:EC2/PortProbeUnprotectedPort',
            'Severity':7,'Description':'SECRET','Resource':{'SECRET':'SECRET'},'Service':{'Archived':False},'UpdatedAt':NOW.isoformat()}]}
        self.calls.append(('securityhub','GetFindings',p))
        if self.deny:raise ClientError({'Error':{'Code':'AccessDeniedException','Message':'SECRET'}},'GetFindings')
        return {'Findings':[{'Id':'demo','AwsAccountId':ACCOUNT,'Region':'us-east-1','RecordState':'ACTIVE',
            'Severity':{'Label':'HIGH'},'Workflow':{'Status':'NEW'},'Description':'SECRET','Resources':[{'Type':'AwsEc2Instance','Details':{'SECRET':'SECRET'}}]}]}
    def describe_alarms(self,**p):
        self.calls.append(('cloudwatch','DescribeAlarms',p))
        key='MetricAlarms' if p['AlarmTypes']==['MetricAlarm'] else 'CompositeAlarms'
        return {key:[{'AlarmArn':'arn:aws:cloudwatch:us-east-1:'+ACCOUNT+':alarm:demo','StateValue':'ALARM',
            'StateReason':'SECRET','StateReasonData':'SECRET','StateUpdatedTimestamp':NOW}]}
    def lookup_events(self,**p):
        self.calls.append(('cloudtrail','LookupEvents',p))
        return {'Events':[{'EventId':'event1','EventName':'ModifyInstanceAttribute','EventSource':'ec2.amazonaws.com','EventTime':NOW,
            'Username':'SECRET','CloudTrailEvent':json.dumps({'errorCode':'AccessDenied','requestParameters':{'password':'SECRET'},'userIdentity':{'accessKeyId':'SECRET'}})}]}
    def describe_stacks(self,**p):return {'Stacks':[{'StackId':'arn:aws:cloudformation:us-east-1:'+ACCOUNT+':stack/demo/id','StackStatus':'UPDATE_ROLLBACK_COMPLETE',
        'Parameters':[{'ParameterValue':'SECRET'}],'Outputs':[{'OutputValue':'SECRET'}]}]}
    def list_stack_resources(self,**p):return {'StackResourceSummaries':[{'LogicalResourceId':'Demo','ResourceType':'AWS::S3::Bucket',
        'ResourceStatus':'CREATE_FAILED','PhysicalResourceId':'SECRET','ResourceStatusReason':'SECRET'}]}
    def describe_services(self,**p):return {'services':[{'serviceArn':'arn:aws:ecs:us-east-1:'+ACCOUNT+':service/demo/app','desiredCount':3,
        'runningCount':1,'pendingCount':1,'status':'ACTIVE','taskDefinition':'demo:1',
        'deployments':[{'rolloutState':'FAILED','rolloutStateReason':'SECRET'}],'events':[{'message':'SECRET'}]}]}
    def describe_task_definition(self,**p):return {'taskDefinition':{'containerDefinitions':[{'privileged':True,
        'environment':[{'name':'SECRET','value':'SECRET'}],'secrets':[{'valueFrom':'SECRET'}]}]}}


def tool(api):
    session=MagicMock();session.client.return_value=api
    return Platform(EvidenceStore(),factory=lambda *args:(session,None)),session


def codes(r):return {f['code'] for f in r['findings']}


def test_security_scoped_sources_metadata_without_secrets(configured):
    api=APIs();platform,_=tool(api)
    result=platform.query('test','us-east-1','security_findings',services=['guardduty','securityhub'])
    assert result['status']=='degraded' and result['summary']['observed_findings']=={'guardduty':1,'securityhub':1}
    assert not result['summary']['clean_security_verified']
    assert 'SECRET' not in json.dumps(platform.store.get(result['evidence_id']))
    assert api.calls[0][2]['FindingCriteria']['Criterion']['accountId']['Eq']==[ACCOUNT]
    assert type(api.calls[0][2]['FindingCriteria']['Criterion']['severity']['Gte']) is int
    validate_parameters(api.calls[0][2],botocore.session.get_session().get_service_model('guardduty').operation_model('ListFindings').input_shape)


def test_guardduty_threshold_must_match_integer_sdk_contract(configured):
    platform,session=tool(APIs())
    result=platform.query('test','us-east-1','security_findings',services=['guardduty'],minimum_severity=4.5)
    assert result['errors'][0]['code']=='invalid_guardduty_severity'
    session.client.assert_not_called()


@pytest.mark.parametrize('flag,code',[('detectors','guardduty_no_detector_observed'),('disabled','guardduty_detector_not_enabled')])
def test_no_detector_or_disabled_is_partial_not_clean(configured,flag,code):
    api=APIs();setattr(api,flag,False if flag=='detectors' else True);platform,_=tool(api)
    result=platform.query('test','us-east-1','security_findings',services=['guardduty'])
    assert result['status']=='partial' and result['errors'][0]['code']==code
    assert not result['summary']['clean_security_verified']


def test_foreign_finding_rejected_and_other_source_denied_preserves_evidence(configured):
    api=APIs();api.foreign=True;platform,_=tool(api)
    result=platform.query('test','us-east-1','security_findings',services=['guardduty'])
    assert result['errors'][0]['code']=='finding_scope_mismatch'
    api.foreign=False;api.deny=True
    result=platform.query('test','us-east-1','security_findings',services=['guardduty','securityhub'])
    assert result['status']=='partial' and result['summary']['observed_findings']=={'guardduty':1}
    assert result['errors'][0]['code']=='access_denied'


def test_alarm_and_management_timeline_does_not_claim_cause_or_echo_payload(configured):
    api=APIs();platform,_=tool(api)
    result=platform.query('test','us-east-1','incident',alarm_prefix='demo',resource_name='demo',**WINDOW)
    assert result['status']=='degraded' and result['summary']['permission_denied_events']==1
    assert not result['summary']['root_cause_verified'] and result['summary']['alarm_states']=={'ALARM':2}
    assert 'SECRET' not in json.dumps(platform.store.get(result['evidence_id']))


def test_alarm_only_and_invalid_window_before_aws(configured):
    api=APIs();api.lookup_events=MagicMock();platform,session=tool(api)
    result=platform.query('test','us-east-1','incident',alarm_prefix='demo',include_cloudtrail=False)
    assert result['status']=='degraded';api.lookup_events.assert_not_called()
    session.reset_mock()
    invalid=platform.query('test','us-east-1','incident',alarm_prefix='demo',resource_name='demo',start_time=NOW.isoformat(),end_time=NOW.isoformat())
    assert invalid['status']=='error';session.client.assert_not_called()


def test_malformed_cloudtrail_is_partial(configured):
    api=APIs();api.lookup_events=lambda **p:{'Events':[{'EventId':'e','EventName':'Call','CloudTrailEvent':'not json'}]};platform,_=tool(api)
    result=platform.query('test','us-east-1','incident',alarm_prefix='demo',resource_name='demo',**WINDOW)
    assert result['status']=='partial' and result['errors'][0]['code']=='cloudtrail_event_parse_failed'


def plan_change(type_,actions,after=None,unknown=None):
    return {'format_version':'1.2','resource_changes':[{'address':'SECRET','type':type_,
        'change':{'actions':actions,'after':after,'after_unknown':unknown or {},'before':{'password':'SECRET'}}}],
        'planned_values':{'outputs':{'password':{'value':'SECRET'}}}}


def test_plan_destruction_encryption_and_values_never_echoed():
    result=plan_query(json.dumps(plan_change('aws_db_instance',['delete','create'],{'storage_encrypted':False,'password':'SECRET'})))
    assert result['status']=='degraded' and result['summary']['actions']=={'replace':1}
    assert {'planned_destruction_or_replacement','planned_storage_encryption_disabled'}<=codes(result)
    assert not result['summary']['apply_executed'] and not result['summary']['live_drift_verified']
    assert 'SECRET' not in json.dumps(result)


def test_unknown_values_do_not_assert_configuration_and_false_mask_is_known():
    result=plan_query(json.dumps(plan_change('aws_db_instance',['create'],{'storage_encrypted':False},{'storage_encrypted':True})))
    assert 'planned_storage_encryption_disabled' not in codes(result)
    assert result['summary']['resources_with_unknown_values']==1
    known=plan_query(json.dumps(plan_change('aws_db_instance',['create'],{'storage_encrypted':False},{'storage_encrypted':False})))
    assert known['summary']['resources_with_unknown_values']==0 and 'planned_storage_encryption_disabled' in codes(known)


@pytest.mark.parametrize('value',['{}','not json',json.dumps({'format_version':'2.0'}),json.dumps(plan_change('aws_db_instance',['execute']))])
def test_invalid_plans_are_errors(value):
    result=plan_query(value)
    assert result['status']=='error' and not result['coverage']['complete']


def test_cloudformation_ecs_status_and_secret_omission(configured):
    api=APIs();platform,_=tool(api)
    stack=platform.query('test','us-east-1','cloudformation',stack_name='demo')
    assert {'stack_failed_or_rolled_back','stack_resource_failed'}<=codes(stack)
    assert 'SECRET' not in json.dumps(platform.store.get(stack['evidence_id']))
    ecs=platform.query('test','us-east-1','ecs',cluster_name='demo',service_name='app')
    assert {'ecs_running_below_desired','ecs_rollout_failed','ecs_privileged_container_configured'}<=codes(ecs)
    assert not ecs['summary']['application_health_verified'] and 'SECRET' not in json.dumps(platform.store.get(ecs['evidence_id']))


def test_ecs_failures_are_not_healthy(configured):
    api=APIs();api.describe_services=lambda **p:{'services':[],'failures':[{'reason':'MISSING','detail':'SECRET'}]};platform,_=tool(api)
    result=platform.query('test','us-east-1','ecs',cluster_name='demo',service_name='app')
    assert not result['coverage']['complete'] and result['errors'][0]['code']=='ecs_service_not_observed'
    assert 'SECRET' not in json.dumps(result)


def test_sdk_shapes():
    session=botocore.session.get_session();api=APIs();platform,_=tool(api)
    # Include real model validation of all constructed filters and pagination parameters.
    calls=[('guardduty','ListDetectors',{}),('guardduty','GetDetector',{'DetectorId':DETECTOR}),
        ('guardduty','ListFindings',{'DetectorId':DETECTOR,'FindingCriteria':{'Criterion':{'accountId':{'Eq':[ACCOUNT]},'severity':{'Gte':4},'service.archived':{'Eq':['false']}}}}),
        ('guardduty','GetFindings',{'DetectorId':DETECTOR,'FindingIds':[FINDING]}),
        ('securityhub','GetFindings',{'Filters':{'AwsAccountId':[{'Value':ACCOUNT,'Comparison':'EQUALS'}],'Region':[{'Value':'us-east-1','Comparison':'EQUALS'}],'RecordState':[{'Value':'ACTIVE','Comparison':'EQUALS'}],'WorkflowStatus':[{'Value':'NEW','Comparison':'EQUALS'}]},'MaxResults':100}),
        ('cloudwatch','DescribeAlarms',{'AlarmNamePrefix':'demo','AlarmTypes':['CompositeAlarm'],'MaxRecords':100}),
        ('cloudtrail','LookupEvents',{'LookupAttributes':[{'AttributeKey':'ResourceName','AttributeValue':'demo'}],'StartTime':NOW-timedelta(hours=1),'EndTime':NOW,'MaxResults':50}),
        ('cloudformation','DescribeStacks',{'StackName':'demo'}),('cloudformation','ListStackResources',{'StackName':'demo'}),
        ('ecs','DescribeServices',{'cluster':'demo','services':['app']}),('ecs','DescribeTaskDefinition',{'taskDefinition':'demo:1'})]
    for service,name,params in calls:validate_parameters(params,session.get_service_model(service).operation_model(name).input_shape)
