"""Targeted CloudFormation/ECS metadata diagnostics; no templates, outputs or environment values."""
import re
from datetime import datetime
from collections import Counter
from .eks_cli import CollectionError


def validate(kind,params):
    if kind=='cloudformation':
        if not re.fullmatch(r'[A-Za-z][A-Za-z0-9-]{0,127}',params.get('stack_name','')):raise CollectionError('invalid_stack_name')
    elif kind=='ecs':
        if any(not re.fullmatch(r'[A-Za-z0-9_-]{1,255}',params.get(k,'')) for k in ('cluster_name','service_name')):
            raise CollectionError('invalid_ecs_target')


def finding(result,code,resource,severity='warning',**evidence):
    result['findings'].append({'code':code,'resource_id':resource,'severity':severity,'confidence':'confirmed',
        'evidence':evidence,'recommendations':['Inspect deployment configuration and intended availability requirements']})


def cloudformation(context,result,stack_name):
    stacks=context.call('cloudformation','describe_stacks',StackName=stack_name).get('Stacks',[])
    if len(stacks)!=1:raise CollectionError('stack_not_unique')
    stack=stacks[0];arn=stack['StackId'];state=stack['StackStatus']
    drift_time=stack.get('DriftInformation',{}).get('LastCheckTimestamp')
    result['items'].append({'kind':'cloudformation_stack','resource_id':arn,'status':state,
        'termination_protection':stack.get('EnableTerminationProtection'),'drift_status':stack.get('DriftInformation',{}).get('StackDriftStatus','NOT_CHECKED'),
        'drift_checked_at':drift_time.isoformat() if isinstance(drift_time,datetime) else None})
    if 'FAILED' in state or 'ROLLBACK' in state:finding(result,'stack_failed_or_rolled_back',arn,status=state)
    counts=Counter()
    for resource in context.pages('cloudformation','list_stack_resources','StackResourceSummaries',StackName=stack_name):
        status=resource.get('ResourceStatus','unknown');counts[status]+=1
        result['items'].append({'kind':'stack_resource','logical_id':resource['LogicalResourceId'],
            'type':resource['ResourceType'],'status':status,'drift_status':resource.get('DriftInformation',{}).get('StackResourceDriftStatus','NOT_CHECKED')})
        if 'FAILED' in status:finding(result,'stack_resource_failed',arn,logical_id=resource['LogicalResourceId'],status=status)
    result['summary'].update(resource_states=dict(counts),assessment='observed_stack_status_only',live_drift_check_executed=False)
    result['coverage']['exclusions']=['templates','parameters/outputs','status reasons/custom physical IDs','new drift detection',
                                     'StackSets','rollback execution','application acceptance']


def ecs(context,result,cluster_name,service_name):
    raw=context.call('ecs','describe_services',cluster=cluster_name,services=[service_name])
    services=raw.get('services',[])
    if raw.get('failures') or len(services)!=1:raise CollectionError('ecs_service_not_observed')
    service=services[0];arn=service['serviceArn'];desired=service['desiredCount'];running=service['runningCount']
    result['items'].append({'kind':'ecs_service','resource_id':arn,'status':service.get('status'),'desired':desired,
        'running':running,'pending':service.get('pendingCount'),'launch_type':service.get('launchType'),
        'deployment_controller':service.get('deploymentController',{}).get('type'),
        'execute_command_enabled':service.get('enableExecuteCommand',False)})
    if running<desired:finding(result,'ecs_running_below_desired',arn,desired=desired,running=running)
    if desired==0:finding(result,'ecs_service_scaled_to_zero',arn,'info')
    for deployment in service.get('deployments',[]):
        result['items'].append({'kind':'ecs_deployment','status':deployment.get('status'),'rollout_state':deployment.get('rolloutState'),
            'desired':deployment.get('desiredCount'),'running':deployment.get('runningCount'),'failed_tasks':deployment.get('failedTasks')})
        if deployment.get('rolloutState')=='FAILED':finding(result,'ecs_rollout_failed',arn)
    task=context.call('ecs','describe_task_definition',taskDefinition=service['taskDefinition'])['taskDefinition']
    linux=task.get('runtimePlatform',{}).get('operatingSystemFamily','LINUX')=='LINUX'
    for index,container in enumerate(task.get('containerDefinitions',[])):
        result['items'].append({'kind':'task_container','container_index':index,'privileged':container.get('privileged',False),
            'readonly_root_filesystem':container.get('readonlyRootFilesystem',False),
            'environment_entries_omitted':len(container.get('environment',[])),'secret_references_omitted':len(container.get('secrets',[]))})
        if container.get('privileged'):finding(result,'ecs_privileged_container_configured',arn,container_index=index)
        if linux and not container.get('readonlyRootFilesystem',False):finding(result,'ecs_writable_root_filesystem',arn,'info',container_index=index)
    result['summary'].update(assessment='ecs_service_and_task_configuration',application_health_verified=False)
    result['coverage']['exclusions']=['container environment/secret values','task/container runtime health','ELB target health',
                                     'logs/events payloads','ECR scanning','CI/CD runners','rollout mutations']
