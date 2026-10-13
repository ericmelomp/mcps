import json
from unittest.mock import MagicMock
import pytest
import botocore.session
from botocore.validate import validate_parameters
from aws_ops_mcp.platform_ops import Platform
from aws_ops_mcp.evidence import EvidenceStore

ACCOUNT='000000000000'


class APIs:
    def __init__(self):self.bad_url=False;self.calls=[]
    def get_function_configuration(self,**p):return {'FunctionArn':'arn:aws:lambda:us-east-1:'+ACCOUNT+':function:demo',
        'State':'Failed','LastUpdateStatus':'Failed','StateReason':'SECRET','Environment':{'Variables':{'TOKEN':'SECRET'}}}
    def get_function_concurrency(self,**p):return {'ReservedConcurrentExecutions':0}
    def get_queue_url(self,**p):return {'QueueUrl':'https://evil.example/'+ACCOUNT+'/demo' if self.bad_url else 'https://sqs.us-east-1.amazonaws.com/'+ACCOUNT+'/demo'}
    def get_queue_attributes(self,**p):
        self.calls.append(p)
        return {'Attributes':{'QueueArn':'arn:aws:sqs:us-east-1:'+ACCOUNT+':demo','ApproximateNumberOfMessages':'5',
            'ApproximateNumberOfMessagesNotVisible':'0','ApproximateNumberOfMessagesDelayed':'0','RedrivePolicy':json.dumps({'deadLetterTargetArn':'SECRET'}),'KmsMasterKeyId':'SECRET'}}
    def get_job(self,**p):return {'Job':{'Name':'demo','GlueVersion':'5.0','DefaultArguments':{'--password':'SECRET'},'Command':{'Name':'glueetl','ScriptLocation':'SECRET'}}}
    def get_job_runs(self,**p):return {'JobRuns':[{'Id':'demo-run','JobRunState':'FAILED','ErrorMessage':'SECRET','Arguments':{'password':'SECRET'}}], 'NextToken':'more'}
    def get_knowledge_base(self,**p):return {'knowledgeBase':{'knowledgeBaseArn':'arn:aws:bedrock:us-east-1:'+ACCOUNT+':knowledge-base/0123456789',
        'status':'FAILED','failureReasons':['SECRET'],'knowledgeBaseConfiguration':{'type':'VECTOR'},'storageConfiguration':{'type':'OPENSEARCH_SERVERLESS','credentials':'SECRET'}}}
    def describe_endpoint(self,**p):return {'EndpointArn':'arn:aws:sagemaker:us-east-1:'+ACCOUNT+':endpoint/demo','EndpointStatus':'Failed',
        'EndpointConfigName':'demo','FailureReason':'SECRET'}
    def describe_endpoint_config(self,**p):return {'DataCaptureConfig':{'EnableCapture':True,'DestinationS3Uri':'SECRET'},'KmsKeyId':'SECRET'}


def tool(api):
    session=MagicMock();session.client.return_value=api
    return Platform(EvidenceStore(),factory=lambda *args:(session,None)),session


def codes(result):return {f['code'] for f in result['findings']}


@pytest.mark.parametrize('kind,params,expected',[
    ('serverless',{'service_kind':'lambda','resource_name':'demo'},'lambda_reserved_concurrency_zero'),
    ('serverless',{'service_kind':'sqs','resource_name':'demo'},'queue_messages_waiting_observed'),
    ('analytics',{'resource_name':'demo'},'glue_run_failed_or_timed_out'),
    ('ai',{'resource_kind':'knowledge_base','resource_name':'0123456789'},'knowledge_base_failure_observed'),
    ('ai',{'resource_kind':'sagemaker_endpoint','resource_name':'demo'},'sagemaker_endpoint_failure_observed')])
def test_application_metadata_signals_and_secrets_never_echoed(configured,kind,params,expected):
    api=APIs();platform,_=tool(api);result=platform.query('test','us-east-1',kind,**params)
    assert result['status']=='degraded' and expected in codes(result)
    assert 'SECRET' not in json.dumps(platform.store.get(result['evidence_id']))
    assert all(name not in [row.get('operation') for row in result['items']] for name in ('invoke','receive_message','start_job_run','invoke_model'))


def test_queue_endpoint_is_checked_before_attributes(configured):
    api=APIs();api.bad_url=True;platform,_=tool(api)
    result=platform.query('test','us-east-1','serverless',service_kind='sqs',resource_name='demo')
    assert result['errors'][0]['code']=='queue_endpoint_scope_mismatch' and not api.calls


def test_glue_history_is_explicitly_limited(configured):
    platform,_=tool(APIs());result=platform.query('test','us-east-1','analytics',resource_name='demo')
    assert result['summary']['recent_run_limit']==20 and result['summary']['more_runs_available']
    assert not result['coverage']['history_complete'] and not result['summary']['data_pipeline_verified']


@pytest.mark.parametrize('analysis,params',[
    ('serverless',{'service_kind':'lambda','resource_name':'bad.function'}),
    ('serverless',{'service_kind':'sqs','resource_name':'https://evil.test'}),
    ('ai',{'resource_kind':'knowledge_base','resource_name':'bad'}),
    ('analytics',{'resource_name':'bad;command'})])
def test_input_rejected_before_client_calls(configured,analysis,params):
    platform,session=tool(APIs());result=platform.query('test','us-east-1',analysis,**params)
    assert result['status']=='error';session.client.assert_not_called()


def test_method_allowlist_contains_no_exec_or_payload_calls():
    from aws_ops_mcp.ops_runtime import OPERATIONS
    for service in ('lambda','sqs','glue','bedrock-agent','sagemaker'):
        assert all(method.startswith(('get_','describe_')) for method in OPERATIONS[service])


def test_sdk_parameter_shapes():
    session=botocore.session.get_session()
    calls=[('lambda','GetFunctionConfiguration',{'FunctionName':'demo'}),('lambda','GetFunctionConcurrency',{'FunctionName':'demo'}),
        ('sqs','GetQueueUrl',{'QueueName':'demo','QueueOwnerAWSAccountId':ACCOUNT}),
        ('sqs','GetQueueAttributes',{'QueueUrl':'https://sqs.us-east-1.amazonaws.com/'+ACCOUNT+'/demo','AttributeNames':['QueueArn','ApproximateNumberOfMessages','ApproximateNumberOfMessagesNotVisible','ApproximateNumberOfMessagesDelayed','VisibilityTimeout','MessageRetentionPeriod','RedrivePolicy','KmsMasterKeyId','SqsManagedSseEnabled']}),
        ('glue','GetJob',{'JobName':'demo'}),('glue','GetJobRuns',{'JobName':'demo','MaxResults':20}),
        ('bedrock-agent','GetKnowledgeBase',{'knowledgeBaseId':'0123456789'}),
        ('sagemaker','DescribeEndpoint',{'EndpointName':'demo'}),('sagemaker','DescribeEndpointConfig',{'EndpointConfigName':'demo'})]
    for service,name,params in calls:validate_parameters(params,session.get_service_model(service).operation_model(name).input_shape)
