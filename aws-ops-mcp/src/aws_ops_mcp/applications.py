"""Initial serverless, analytics and AI metadata assessments; no execution/inference or payload reads."""
import json
import re
from urllib.parse import urlsplit
from datetime import datetime
from .eks_cli import CollectionError


def validate(kind,params):
    name=params.get('resource_name','')
    if not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}',name):raise CollectionError('invalid_application_resource_name')
    if kind=='serverless' and params.get('service_kind') not in {'lambda','sqs'}:raise CollectionError('unsupported_serverless_kind')
    if kind=='serverless' and params.get('service_kind')=='lambda' and not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',name):
        raise CollectionError('invalid_function_name')
    if kind=='serverless' and params.get('service_kind')=='sqs' and not re.fullmatch(r'(?:[A-Za-z0-9_-]{1,80}|[A-Za-z0-9_-]{1,75}\.fifo)',name):
        raise CollectionError('invalid_queue_name')
    if kind=='ai' and params.get('resource_kind') not in {'knowledge_base','sagemaker_endpoint'}:raise CollectionError('unsupported_ai_kind')
    if kind=='ai' and params.get('resource_kind')=='knowledge_base' and not re.fullmatch(r'[A-Za-z0-9]{10}',name):
        raise CollectionError('invalid_knowledge_base_id')


def signal(result,code,resource,severity='warning',**evidence):
    result['findings'].append({'code':code,'resource_id':resource,'severity':severity,'confidence':'confirmed',
        'evidence':evidence,'recommendations':['Review observed metadata and confirm workload behavior with application telemetry']})


def serverless(context,result,service_kind,resource_name):
    if service_kind=='lambda':
        config=context.call('lambda','get_function_configuration',FunctionName=resource_name)
        concurrency=context.call('lambda','get_function_concurrency',FunctionName=resource_name).get('ReservedConcurrentExecutions')
        arn=config['FunctionArn']
        result['items'].append({'kind':'lambda_configuration','resource_id':arn,'state':config.get('State'),
            'update_status':config.get('LastUpdateStatus'),'runtime':config.get('Runtime'),'memory_mib':config.get('MemorySize'),
            'timeout_seconds':config.get('Timeout'),'reserved_concurrency':concurrency,
            'vpc_subnet_count':len(config.get('VpcConfig',{}).get('SubnetIds',[])),
            'environment_values_omitted':len(config.get('Environment',{}).get('Variables',{})),
            'dead_letter_target_configured':bool(config.get('DeadLetterConfig',{}).get('TargetArn'))})
        if config.get('State')=='Failed' or config.get('LastUpdateStatus')=='Failed':signal(result,'lambda_state_or_update_failed',arn)
        if concurrency==0:signal(result,'lambda_reserved_concurrency_zero',arn)
    else:
        url=context.call('sqs','get_queue_url',QueueName=resource_name,QueueOwnerAWSAccountId=context.account_id)['QueueUrl']
        parsed=urlsplit(url)
        if parsed.scheme!='https' or parsed.netloc!=f'sqs.{context.region}.amazonaws.com' or parsed.query or parsed.fragment or not parsed.path.startswith('/'+context.account_id+'/'):
            raise CollectionError('queue_endpoint_scope_mismatch')
        wanted=['QueueArn','ApproximateNumberOfMessages','ApproximateNumberOfMessagesNotVisible','ApproximateNumberOfMessagesDelayed',
                'VisibilityTimeout','MessageRetentionPeriod','RedrivePolicy','KmsMasterKeyId','SqsManagedSseEnabled']
        attrs=context.call('sqs','get_queue_attributes',QueueUrl=url,AttributeNames=wanted).get('Attributes',{})
        arn=attrs['QueueArn'];counts={}
        for key in wanted[1:4]:
            value=attrs.get(key)
            if value is None or not re.fullmatch(r'\d{1,18}',value):raise CollectionError('queue_count_unobserved_or_invalid')
            counts[key]=int(value)
        dlq=False
        if attrs.get('RedrivePolicy'):
            policy=json.loads(attrs['RedrivePolicy']);dlq=bool(policy.get('deadLetterTargetArn'))
        result['items'].append({'kind':'sqs_configuration','resource_id':arn,'approximate_counts':counts,
            'visibility_timeout_seconds':attrs.get('VisibilityTimeout'),'retention_seconds':attrs.get('MessageRetentionPeriod'),
            'dead_letter_target_configured':dlq,'kms_key_configured':bool(attrs.get('KmsMasterKeyId')),
            'sqs_managed_sse':attrs.get('SqsManagedSseEnabled')})
        if counts['ApproximateNumberOfMessages']>0:signal(result,'queue_messages_waiting_observed',arn,'info',approximate_count=counts['ApproximateNumberOfMessages'])
        if not dlq:signal(result,'queue_dlq_not_configured',arn,'info')
    result['summary'].update(assessment='serverless_configuration_only',invocation_or_message_processing_verified=False)
    result['coverage']['exclusions']=['function invocation','queue send/receive/delete','message bodies','Lambda code/env values',
        'runtime logs/metrics','API Gateway/EventBridge/Step Functions integrations','idempotency/retry verification']


def analytics(context,result,resource_name):
    job=context.call('glue','get_job',JobName=resource_name)['Job']
    result['items'].append({'kind':'glue_job','resource_id':resource_name,'version':job.get('GlueVersion'),
        'command_type':job.get('Command',{}).get('Name'),'worker_type':job.get('WorkerType'),'workers':job.get('NumberOfWorkers'),
        'timeout_minutes':job.get('Timeout'),'security_configuration_present':bool(job.get('SecurityConfiguration')),
        'default_arguments_omitted':len(job.get('DefaultArguments',{}))})
    response=context.call('glue','get_job_runs',JobName=resource_name,MaxResults=20)
    runs=response.get('JobRuns',[])
    if len(runs)>20:raise CollectionError('glue_run_limit')
    for run in runs:
        stamp=run.get('CompletedOn',run.get('StartedOn'))
        result['items'].append({'kind':'glue_run','resource_id':run['Id'],'state':run.get('JobRunState'),
            'timestamp':stamp.isoformat() if isinstance(stamp,datetime) else None,'execution_seconds':run.get('ExecutionTime')})
        if run.get('JobRunState') in {'FAILED','TIMEOUT','ERROR'}:signal(result,'glue_run_failed_or_timed_out',run['Id'],state=run['JobRunState'])
    result['summary'].update(assessment='glue_configuration_and_recent_run_status',observed_runs=len(runs),
        recent_run_limit=20,more_runs_available=bool(response.get('NextToken')),data_pipeline_verified=False)
    result['coverage'].update(history_complete=False,exclusions=['script/arguments/log contents','data contents',
        'security configuration policy evaluation','costs','Athena/Redshift/EMR/MSK/Lake Formation','job start/retry'])


def ai(context,result,resource_kind,resource_name):
    if resource_kind=='knowledge_base':
        kb=context.call('bedrock-agent','get_knowledge_base',knowledgeBaseId=resource_name)['knowledgeBase'];arn=kb['knowledgeBaseArn']
        result['items'].append({'kind':'bedrock_knowledge_base','resource_id':arn,'status':kb.get('status'),
            'knowledge_base_type':kb.get('knowledgeBaseConfiguration',{}).get('type'),
            'storage_type':kb.get('storageConfiguration',{}).get('type'),'failure_reasons_omitted':len(kb.get('failureReasons',[]))})
        if kb.get('status') in {'FAILED','DELETE_UNSUCCESSFUL'}:signal(result,'knowledge_base_failure_observed',arn,state=kb.get('status'))
    else:
        endpoint=context.call('sagemaker','describe_endpoint',EndpointName=resource_name);arn=endpoint['EndpointArn']
        config=context.call('sagemaker','describe_endpoint_config',EndpointConfigName=endpoint['EndpointConfigName'])
        result['items'].append({'kind':'sagemaker_endpoint','resource_id':arn,'status':endpoint.get('EndpointStatus'),
            'production_variants':len(endpoint.get('ProductionVariants',[])),
            'data_capture_configured':bool(config.get('DataCaptureConfig',{}).get('EnableCapture')),
            'kms_key_configured':bool(config.get('KmsKeyId'))})
        if endpoint.get('EndpointStatus') in {'Failed','OutOfService','UpdateRollbackFailed'}:signal(result,'sagemaker_endpoint_failure_observed',arn,status=endpoint.get('EndpointStatus'))
    result['summary'].update(assessment='ai_resource_configuration_only',inference_or_retrieval_verified=False)
    result['coverage']['exclusions']=['inference/retrieval/model calls','prompts/documents/connection details','runtime costs',
        'model access authorization','Bedrock Agents/AgentCore/Guardrails','training/MLOps','underlying IAM/KMS permissions']
