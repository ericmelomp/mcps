"""Explicit resource assessments with targeted metadata, deterministic risks and bounded metrics."""
import math
import re
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from botocore.exceptions import ClientError
from .eks_cli import CollectionError
from .ops_runtime import safe_error


def signal(result,code,resource,severity='warning',confidence='confirmed',**evidence):
    result['findings'].append({'code':code,'resource_id':resource,'severity':severity,'confidence':confidence,
                               'evidence':evidence,'recommendations':['Review observed configuration against workload requirements']})


def validate(analysis,params):
    if analysis=='compute':
        ids=params.get('instance_ids',[])
        if not 1<=len(ids)<=5 or len(ids)!=len(set(ids)) or any(not re.fullmatch(r'i-(?:[a-f0-9]{8}|[a-f0-9]{17})',v) for v in ids):
            raise CollectionError('invalid_instance_selection')
        hours=params.get('hours',24)
        if type(hours) is not int or not 24<=hours<=336:raise CollectionError('invalid_metric_window')
    elif analysis=='database':
        if params.get('database_kind') not in {'rds','aurora','dynamodb','elasticache'}:
            raise CollectionError('unsupported_database_kind')
        if not re.fullmatch(r'[a-zA-Z0-9_.-]{1,255}',params.get('resource_name','')):raise CollectionError('invalid_database_name')
    elif analysis=='storage':
        bucket=params.get('bucket_name','')
        if not re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]',bucket) or '..' in bucket:
            raise CollectionError('invalid_bucket_name')
    elif analysis=='backup':
        arn=params.get('resource_arn','')
        if not re.fullmatch(r'arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[A-Za-z0-9_+=,.@:/-]{1,1024}',arn):
            raise CollectionError('invalid_resource_arn')
        age=params.get('maximum_age_hours',24)
        if type(age) is not int or not 1<=age<=8760:raise CollectionError('invalid_backup_age')


def metrics(context,result,instance_ids,hours):
    end=datetime.now(timezone.utc);start=end-timedelta(hours=hours)
    definitions={}
    queries=[]
    for i,instance in enumerate(instance_ids):
        for j,(name,stat) in enumerate([('CPUUtilization','Average'),('CPUUtilization','Maximum'),('NetworkIn','Sum'),('NetworkOut','Sum')]):
            identifier=f'm{i}_{j}';definitions[identifier]=(instance,name,stat)
            queries.append({'Id':identifier,'MetricStat':{'Metric':{'Namespace':'AWS/EC2','MetricName':name,
                'Dimensions':[{'Name':'InstanceId','Value':instance}]},'Period':3600,'Stat':stat},'ReturnData':True})
    values=defaultdict(dict);statuses=defaultdict(set)
    for record in context.pages('cloudwatch','get_metric_data','MetricDataResults',MetricDataQueries=queries,
                                StartTime=start,EndTime=end,ScanBy='TimestampAscending',MaxDatapoints=10080):
        identifier=record.get('Id')
        if identifier not in definitions:raise CollectionError('unexpected_metric_id')
        statuses[identifier].add(record.get('StatusCode','Unknown'))
        samples=record.get('Values',[]);timestamps=record.get('Timestamps',[])
        if len(samples)!=len(timestamps):raise CollectionError('metric_samples_mismatch')
        for stamp,value in zip(timestamps,samples):
            if not isinstance(stamp,datetime) or stamp.tzinfo is None or not start<=stamp<end:continue
            if isinstance(value,bool) or not isinstance(value,(int,float)) or not math.isfinite(value):raise CollectionError('invalid_metric_value')
            if stamp in values[identifier] and values[identifier][stamp]!=value:raise CollectionError('conflicting_metric_sample')
            values[identifier][stamp]=value
            if len(values[identifier])>336:raise CollectionError('metric_sample_limit')
    for identifier,(resource,name,stat) in definitions.items():
        observed=list(values[identifier].values());complete=statuses[identifier]=={'Complete'} and len(observed)>=hours-1
        result['items'].append({'kind':'historical_metric','resource_id':resource,'metric':name,'stat':stat,
            'period_seconds':3600,'samples':len(observed),'expected_hours':hours,'coverage_complete':complete,
            'mean_of_hourly_values':sum(observed)/len(observed) if observed else None,'maximum_observed':max(observed) if observed else None,
            'start':start.isoformat(),'end_exclusive':end.isoformat()})
        if not complete:result['errors'].append({'code':'historical_metric_incomplete','component':name,'resource_id':resource})
    result['summary']['memory_metrics_available']=False


def compute(context,result,instance_ids,hours=24,include_metrics=False):
    observed=[];volume_ids=set()
    for reservation in context.pages('ec2','describe_instances','Reservations',InstanceIds=instance_ids):
        for instance in reservation.get('Instances',[]):
            identifier=instance['InstanceId'];observed.append(identifier)
            if identifier not in instance_ids:raise CollectionError('unexpected_instance')
            metadata=instance.get('MetadataOptions',{})
            result['items'].append({'kind':'compute_instance','resource_id':identifier,'state':instance.get('State',{}).get('Name'),
                'type':instance.get('InstanceType'),'architecture':instance.get('Architecture'),'lifecycle':instance.get('InstanceLifecycle','on-demand'),
                'az':instance.get('Placement',{}).get('AvailabilityZone'),'public_ip_present':bool(instance.get('PublicIpAddress')),
                'imds_tokens':metadata.get('HttpTokens'),'imds_state':metadata.get('State')})
            if metadata.get('HttpEndpoint')=='enabled' and metadata.get('HttpTokens')=='optional':signal(result,'imds_v1_allowed',identifier)
            if instance.get('PublicIpAddress'):signal(result,'instance_public_ip_observed',identifier,'info','possible')
            volume_ids.update(b['Ebs']['VolumeId'] for b in instance.get('BlockDeviceMappings',[]) if b.get('Ebs'))
    if set(observed)!=set(instance_ids):result['errors'].append({'code':'instance_selection_incomplete','component':'instances'})
    if volume_ids:
        if len(volume_ids)>100:raise CollectionError('volume_selection_limit')
        volumes=[]
        for volume in context.pages('ec2','describe_volumes','Volumes',VolumeIds=sorted(volume_ids)):
            volumes.append(volume['VolumeId'])
            result['items'].append({'kind':'attached_volume','resource_id':volume['VolumeId'],'encrypted':volume.get('Encrypted'),
                'type':volume.get('VolumeType'),'size_gib':volume.get('Size'),'state':volume.get('State')})
            if volume.get('Encrypted') is False:signal(result,'ebs_unencrypted',volume['VolumeId'],'high')
        if set(volumes)!=volume_ids:result['errors'].append({'code':'volume_selection_incomplete','component':'volumes'})
    if include_metrics:
        try:metrics(context,result,observed,hours)
        except Exception as exc:result['errors'].append({'code':safe_error(exc),'component':'metrics'})
    result['summary'].update(assessment='compute_configuration_and_observed_metrics',observed_instances=len(observed),
        rightsizing_verified=False,memory_metrics_available=False)
    result['coverage']['exclusions']=['guest OS/user data','application health','ASG policies','Compute Optimizer',
                                     'memory agent metrics','proven idle resources','automatic rightsizing']


def database(context,result,database_kind,resource_name):
    if database_kind=='rds':
        rows=context.call('rds','describe_db_instances',DBInstanceIdentifier=resource_name).get('DBInstances',[])
        if len(rows)!=1:raise CollectionError('database_not_unique')
        db=rows[0];resource=db['DBInstanceArn']
        result['items'].append({'kind':'rds_instance','resource_id':resource,'status':db.get('DBInstanceStatus'),
            'engine':db.get('Engine'),'class':db.get('DBInstanceClass'),'multi_az':db.get('MultiAZ'),
            'publicly_accessible':db.get('PubliclyAccessible'),'storage_encrypted':db.get('StorageEncrypted'),
            'backup_retention_days':db.get('BackupRetentionPeriod'),'deletion_protection':db.get('DeletionProtection'),
            'sg_ids':[g['VpcSecurityGroupId'] for g in db.get('VpcSecurityGroups',[])]})
        if db.get('DBInstanceStatus')!='available':signal(result,'rds_not_available',resource,'warning',state=db.get('DBInstanceStatus'))
        if db.get('MultiAZ') is False:signal(result,'rds_single_az',resource,'info')
        if db.get('PubliclyAccessible'):signal(result,'database_public_access_configured',resource,'warning','possible')
        if db.get('StorageEncrypted') is False:signal(result,'database_storage_unencrypted',resource,'high')
        if db.get('BackupRetentionPeriod')==0:signal(result,'database_automated_backup_disabled',resource,'high')
    elif database_kind=='aurora':
        rows=context.call('rds','describe_db_clusters',DBClusterIdentifier=resource_name).get('DBClusters',[])
        if len(rows)!=1:raise CollectionError('database_not_unique')
        db=rows[0];resource=db['DBClusterArn']
        if not db.get('Engine','').startswith('aurora'):raise CollectionError('not_an_aurora_cluster')
        result['items'].append({'kind':'aurora_cluster','resource_id':resource,'status':db.get('Status'),'engine':db.get('Engine'),
            'storage_encrypted':db.get('StorageEncrypted'),'backup_retention_days':db.get('BackupRetentionPeriod'),
            'deletion_protection':db.get('DeletionProtection'),'members':[{'id':m['DBInstanceIdentifier'],'writer':m.get('IsClusterWriter')} for m in db.get('DBClusterMembers',[])]})
        if db.get('StorageEncrypted') is False:signal(result,'database_storage_unencrypted',resource,'high')
        if len(db.get('DBClusterMembers',[]))<2:signal(result,'aurora_single_instance_observed',resource,'info')
        if db.get('Status')!='available':signal(result,'aurora_not_available',resource,'warning',state=db.get('Status'))
    elif database_kind=='dynamodb':
        db=context.call('dynamodb','describe_table',TableName=resource_name)['Table'];resource=db['TableArn']
        result['items'].append({'kind':'dynamodb_table','resource_id':resource,'status':db.get('TableStatus'),
            'billing_mode':db.get('BillingModeSummary',{}).get('BillingMode','PROVISIONED'),
            'sse_status':db.get('SSEDescription',{}).get('Status','default_encryption_metadata_not_returned'),
            'deletion_protection':db.get('DeletionProtectionEnabled'),'replica_regions':[r['RegionName'] for r in db.get('Replicas',[])]})
        pitr=context.call('dynamodb','describe_continuous_backups',TableName=resource_name)['ContinuousBackupsDescription'].get('PointInTimeRecoveryDescription',{}).get('PointInTimeRecoveryStatus')
        result['items'].append({'kind':'dynamodb_pitr','resource_id':resource,'status':pitr})
        if pitr=='DISABLED':signal(result,'dynamodb_pitr_disabled',resource)
        if pitr is None:result['errors'].append({'code':'pitr_status_unobserved','component':'pitr'})
    else:
        rows=context.call('elasticache','describe_replication_groups',ReplicationGroupId=resource_name).get('ReplicationGroups',[])
        if len(rows)!=1:raise CollectionError('database_not_unique')
        db=rows[0];resource=db.get('ARN',resource_name)
        result['items'].append({'kind':'elasticache_replication_group','resource_id':resource,'status':db.get('Status'),
            'at_rest_encryption':db.get('AtRestEncryptionEnabled'),'transit_encryption':db.get('TransitEncryptionEnabled'),
            'automatic_failover':db.get('AutomaticFailover'),'multi_az':db.get('MultiAZ'),
            'snapshot_retention_days':db.get('SnapshotRetentionLimit')})
        for key,code in [('AtRestEncryptionEnabled','cache_at_rest_encryption_disabled'),('TransitEncryptionEnabled','cache_transit_encryption_disabled')]:
            if db.get(key) is False:signal(result,code,resource)
        if db.get('AutomaticFailover')=='disabled':signal(result,'cache_automatic_failover_disabled',resource,'info')
    result['summary'].update(assessment='database_configuration_only',functional_health_verified=False)
    result['coverage']['exclusions']=['SQL queries','credentials','performance/IOPS metrics','failover tests','backup restore',
                                     'network accessibility','DocumentDB/Neptune/Redshift/MemoryDB']


def storage(context,result,bucket_name):
    common={'Bucket':bucket_name,'ExpectedBucketOwner':context.account_id}
    location=context.call('s3','get_bucket_location',**common).get('LocationConstraint') or 'us-east-1'
    if location=='EU':location='eu-west-1'
    result['items'].append({'kind':'s3_bucket','resource_id':bucket_name,'region':location})
    if location!=context.region:raise CollectionError('bucket_region_mismatch')
    checks=[('get_bucket_encryption','encryption'),('get_bucket_versioning','versioning'),
            ('get_public_access_block','public_access_block'),('get_bucket_policy_status','policy_status'),
            ('get_bucket_lifecycle_configuration','lifecycle')]
    for method,component in checks:
        try:
            value=context.call('s3',method,**common)
            if component=='encryption':
                rules=value['ServerSideEncryptionConfiguration']['Rules']
                result['items'].append({'kind':'s3_encryption','resource_id':bucket_name,
                    'algorithms':[r.get('ApplyServerSideEncryptionByDefault',{}).get('SSEAlgorithm') for r in rules]})
            elif component=='versioning':
                status=value.get('Status','not_enabled');result['items'].append({'kind':'s3_versioning','resource_id':bucket_name,'status':status})
                if status!='Enabled':signal(result,'s3_versioning_not_enabled',bucket_name,'info')
            elif component=='public_access_block':
                block=value['PublicAccessBlockConfiguration'];result['items'].append({'kind':'s3_public_access_block','resource_id':bucket_name,
                    'flags':{k:block.get(k) for k in ('BlockPublicAcls','IgnorePublicAcls','BlockPublicPolicy','RestrictPublicBuckets')}})
                if not all(block.get(k) for k in ('BlockPublicAcls','IgnorePublicAcls','BlockPublicPolicy','RestrictPublicBuckets')):
                    signal(result,'s3_bucket_public_access_block_incomplete',bucket_name,'warning','possible')
            elif component=='policy_status':
                public=value['PolicyStatus']['IsPublic'];result['items'].append({'kind':'s3_policy_status','resource_id':bucket_name,'is_public':public})
                if public:signal(result,'s3_policy_classified_public',bucket_name,'warning','possible')
            else:
                rules=value.get('Rules',[]);result['items'].append({'kind':'s3_lifecycle','resource_id':bucket_name,
                    'rules':len(rules),'enabled_rules':sum(r.get('Status')=='Enabled' for r in rules)})
        except ClientError as exc:
            code=exc.response.get('Error',{}).get('Code')
            absent={'NoSuchBucketPolicy','NoSuchLifecycleConfiguration','NoSuchPublicAccessBlockConfiguration'}
            if code in absent:
                result['items'].append({'kind':'s3_configuration_absent','resource_id':bucket_name,'component':component})
                if component=='public_access_block':signal(result,'s3_bucket_public_access_block_absent',bucket_name,'warning','possible')
            else:result['errors'].append({'code':safe_error(exc),'component':component})
    result['summary'].update(assessment='bucket_configuration_only',object_encryption_verified=False,
                             effective_public_access_verified=False)
    result['coverage']['exclusions']=['object contents/ACLs','account/organization public access controls',
                                     'existing object encryption','restore tests','storage usage/actual savings']


def backup(context,result,resource_arn,maximum_age_hours=24):
    # Cross-account ARNs require the matching configured alias; do not silently inspect a different account.
    if resource_arn.split(':',5)[4]!=context.account_id:raise CollectionError('resource_account_mismatch')
    if resource_arn.split(':',5)[3] and resource_arn.split(':',5)[3]!=context.region:raise CollectionError('resource_region_mismatch')
    now=datetime.now(timezone.utc);completed=[];observed=0
    for point in context.pages('backup','list_recovery_points_by_resource','RecoveryPoints',ResourceArn=resource_arn):
        observed+=1;created=point.get('CreationDate');status=point.get('Status')
        result['items'].append({'kind':'backup_recovery_point','resource_id':point['RecoveryPointArn'],
            'creation_date':created.isoformat() if isinstance(created,datetime) else None,'status':status,
            'vault':point.get('BackupVaultName'),'resource_type':point.get('ResourceType')})
        if status=='COMPLETED' and isinstance(created,datetime) and created.tzinfo is not None and created<=now:completed.append(created)
    latest=max(completed) if completed else None
    age=(now-latest).total_seconds()/3600 if latest else None
    result['summary'].update(assessment='observed_recovery_points_only',observed_points=observed,
        completed_points=len(completed),newest_completed_age_hours=age,maximum_age_hours=maximum_age_hours,restore_verified=False)
    if not latest:signal(result,'no_completed_recovery_point_observed',resource_arn,'warning','possible')
    elif age>maximum_age_hours:signal(result,'backup_older_than_requested_threshold',resource_arn,'warning',age_hours=age)
    result['coverage']['exclusions']=['backups outside AWS Backup','cross-account vaults','retention policy compliance',
                                     'restore verification','business RTO/RPO','native snapshots/PITR']
