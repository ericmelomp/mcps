import json
from datetime import datetime,timezone,timedelta
from unittest.mock import MagicMock
import pytest
import botocore.session
from botocore.exceptions import ClientError
from botocore.validate import validate_parameters
from aws_ops_mcp.platform_ops import Platform
from aws_ops_mcp.evidence import EvidenceStore

ID='i-00000001';ARN='arn:aws:ec2:us-east-1:000000000000:volume/vol-00000001'


class APIs:
    def __init__(self):self.owner=None;self.empty=False;self.deny=False;self.calls=[]
    def describe_instances(self,**p):return {'Reservations':[{'Instances':[{'InstanceId':ID,'State':{'Name':'running'},
        'InstanceType':'m6i.large','MetadataOptions':{'HttpTokens':'optional','HttpEndpoint':'enabled'},
        'PublicIpAddress':'192.0.2.1','UserData':'SECRET','BlockDeviceMappings':[{'Ebs':{'VolumeId':'vol-00000001'}}]}]}]}
    def describe_volumes(self,**p):return {'Volumes':[{'VolumeId':'vol-00000001','Encrypted':False,'Size':20,'State':'in-use'}]}
    def get_metric_data(self,**p):
        self.calls.append(p)
        times=[p['StartTime']+timedelta(hours=i+1) for i in range(23)]
        return {'MetricDataResults':[{'Id':q['Id'],'StatusCode':'Complete','Values':[1.0]*len(times),'Timestamps':times} for q in p['MetricDataQueries']]}
    def describe_db_instances(self,**p):return {'DBInstances':[{'DBInstanceArn':'arn:aws:rds:us-east-1:000000000000:db:demo','DBInstanceStatus':'available',
        'Engine':'postgres','MultiAZ':False,'PubliclyAccessible':True,'StorageEncrypted':False,'BackupRetentionPeriod':0,'MasterUsername':'SECRET'}]}
    def describe_db_clusters(self,**p):return {'DBClusters':[{'DBClusterArn':'arn:aws:rds:us-east-1:000000000000:cluster:demo','Status':'available','Engine':'aurora-postgresql','StorageEncrypted':True,'DBClusterMembers':[{'DBInstanceIdentifier':'demo','IsClusterWriter':True}]}]}
    def describe_table(self,**p):return {'Table':{'TableArn':'arn:aws:dynamodb:us-east-1:000000000000:table/demo','TableStatus':'ACTIVE'}}
    def describe_continuous_backups(self,**p):return {'ContinuousBackupsDescription':{'PointInTimeRecoveryDescription':{'PointInTimeRecoveryStatus':'DISABLED'}}}
    def describe_replication_groups(self,**p):return {'ReplicationGroups':[{'ARN':'arn:aws:elasticache:us-east-1:000000000000:replicationgroup:demo','Status':'available','AtRestEncryptionEnabled':False,'TransitEncryptionEnabled':False,'AutomaticFailover':'disabled'}]}
    def get_bucket_location(self,**p):self.owner=p['ExpectedBucketOwner'];return {'LocationConstraint':None}
    def get_bucket_encryption(self,**p):return {'ServerSideEncryptionConfiguration':{'Rules':[{'ApplyServerSideEncryptionByDefault':{'SSEAlgorithm':'AES256'}}]}}
    def get_bucket_versioning(self,**p):return {}
    def get_public_access_block(self,**p):
        if self.deny:raise ClientError({'Error':{'Code':'AccessDenied','Message':'SECRET'}},'GetPublicAccessBlock')
        return {'PublicAccessBlockConfiguration':dict.fromkeys(['BlockPublicAcls','IgnorePublicAcls','BlockPublicPolicy','RestrictPublicBuckets'],False)}
    def get_bucket_policy_status(self,**p):raise ClientError({'Error':{'Code':'NoSuchBucketPolicy','Message':'SECRET'}},'GetBucketPolicyStatus')
    def get_bucket_lifecycle_configuration(self,**p):raise ClientError({'Error':{'Code':'NoSuchLifecycleConfiguration','Message':'SECRET'}},'GetBucketLifecycleConfiguration')
    def list_recovery_points_by_resource(self,**p):return {'RecoveryPoints':[] if self.empty else [{'RecoveryPointArn':'arn:aws:backup:us-east-1:000000000000:recovery-point:demo','Status':'COMPLETED','CreationDate':datetime.now(timezone.utc)-timedelta(hours=50)}]}


def tool(api):
    session=MagicMock();session.client.return_value=api
    return Platform(EvidenceStore(),factory=lambda *args:(session,None)),session


def codes(result):return {f['code'] for f in result['findings']}


def test_compute_imds_public_ip_volumes_and_metadata_secrets_omitted(configured):
    api=APIs();platform,_=tool(api);result=platform.query('test','us-east-1','compute',instance_ids=[ID])
    assert result['status']=='degraded'
    assert {'imds_v1_allowed','instance_public_ip_observed','ebs_unencrypted'}<=codes(result)
    assert not result['summary']['rightsizing_verified'] and 'SECRET' not in json.dumps(result)


def test_metrics_are_bounded_complete_not_memory_or_idle_proof(configured):
    api=APIs();platform,_=tool(api)
    result=platform.query('test','us-east-1','compute',instance_ids=[ID],include_metrics=True)
    assert result['coverage']['complete'] and result['status']=='degraded'
    rows=platform.store.get(result['evidence_id'])['items']
    metrics=[r for r in rows if r['kind']=='historical_metric']
    assert len(metrics)==4 and all(r['samples']==23 and r['coverage_complete'] for r in metrics)
    assert not result['summary']['memory_metrics_available']
    assert api.calls[0]['MetricDataQueries'][0]['MetricStat']['Period']==3600


def test_missing_metrics_do_not_imply_zero_or_idle(configured):
    api=APIs();api.get_metric_data=lambda **p:{'MetricDataResults':[]};platform,_=tool(api)
    result=platform.query('test','us-east-1','compute',instance_ids=[ID],include_metrics=True)
    assert result['status']=='partial' and result['errors'][0]['code']=='historical_metric_incomplete'


@pytest.mark.parametrize('kind,expected',[('rds','database_storage_unencrypted'),('aurora','aurora_single_instance_observed'),('dynamodb','dynamodb_pitr_disabled'),('elasticache','cache_transit_encryption_disabled')])
def test_database_specific_signals_and_secret_omission(configured,kind,expected):
    api=APIs();platform,_=tool(api)
    result=platform.query('test','us-east-1','database',database_kind=kind,resource_name='demo')
    assert result['status']=='degraded' and expected in codes(result)
    assert not result['summary']['functional_health_verified'] and 'SECRET' not in json.dumps(result)
    if kind=='dynamodb':assert 'database_storage_unencrypted' not in codes(result)


def test_s3_expected_owner_defaults_absent_policy_not_public_proof(configured):
    api=APIs();platform,_=tool(api);result=platform.query('test','us-east-1','storage',bucket_name='demo-bucket')
    assert result['status']=='degraded' and api.owner=='000000000000'
    assert not result['summary']['effective_public_access_verified'] and not result['summary']['object_encryption_verified']
    assert 's3_bucket_public_access_block_incomplete' in codes(result)
    assert 'SECRET' not in json.dumps(result)


def test_s3_denied_component_preserves_other_results(configured):
    api=APIs();api.deny=True;platform,_=tool(api)
    result=platform.query('test','us-east-1','storage',bucket_name='demo-bucket')
    assert result['status']=='partial' and result['errors'][0]['code']=='access_denied'
    assert result['evidence_id']


def test_s3_region_mismatch_stops_config_reads(configured):
    api=APIs();api.get_bucket_location=lambda **p:{'LocationConstraint':'eu-west-1'}
    api.get_bucket_encryption=MagicMock();platform,_=tool(api)
    result=platform.query('test','us-east-1','storage',bucket_name='demo-bucket')
    assert result['errors'][0]['code']=='bucket_region_mismatch'
    api.get_bucket_encryption.assert_not_called()


def test_backup_age_and_restore_unverified(configured):
    api=APIs();platform,_=tool(api)
    result=platform.query('test','us-east-1','backup',resource_arn=ARN,maximum_age_hours=24)
    assert 'backup_older_than_requested_threshold' in codes(result)
    assert not result['summary']['restore_verified'] and result['summary']['completed_points']==1
    api.empty=True
    empty=platform.query('test','us-east-1','backup',resource_arn=ARN)
    assert empty['summary']['newest_completed_age_hours'] is None
    assert 'no_completed_recovery_point_observed' in codes(empty)


@pytest.mark.parametrize('arn,code',[(ARN.replace('000000000000','000000000001'),'resource_account_mismatch'),(ARN.replace('us-east-1','eu-west-1'),'resource_region_mismatch')])
def test_backup_cross_scope_rejected_before_resource_calls(configured,arn,code):
    api=APIs();api.list_recovery_points_by_resource=MagicMock();platform,_=tool(api)
    result=platform.query('test','us-east-1','backup',resource_arn=arn)
    assert result['errors'][0]['code']==code
    api.list_recovery_points_by_resource.assert_not_called()


@pytest.mark.parametrize('analysis,params', [('compute',{'instance_ids':['bad']}),('compute',{'instance_ids':[ID],'hours':999}),
    ('database',{'database_kind':'fake','resource_name':'demo'}),('storage',{'bucket_name':'bad;command'}),
    ('backup',{'resource_arn':ARN,'maximum_age_hours':0})])
def test_inputs_rejected_before_client_use(configured,analysis,params):
    platform,session=tool(APIs());result=platform.query('test','us-east-1',analysis,**params)
    assert result['status']=='error' and not result['coverage']['complete']
    session.client.assert_not_called()


def test_sdk_shapes():
    session=botocore.session.get_session()
    common={'Bucket':'demo-bucket','ExpectedBucketOwner':'000000000000'}
    calls=[('ec2','DescribeInstances',{'InstanceIds':[ID]}),('ec2','DescribeVolumes',{'VolumeIds':['vol-00000001']}),
        ('rds','DescribeDBInstances',{'DBInstanceIdentifier':'demo'}),('rds','DescribeDBClusters',{'DBClusterIdentifier':'demo'}),
        ('dynamodb','DescribeTable',{'TableName':'demo'}),('dynamodb','DescribeContinuousBackups',{'TableName':'demo'}),
        ('elasticache','DescribeReplicationGroups',{'ReplicationGroupId':'demo'}),
        ('backup','ListRecoveryPointsByResource',{'ResourceArn':ARN})]
    calls.extend(('s3',name,common) for name in ['GetBucketLocation','GetBucketEncryption','GetBucketVersioning','GetPublicAccessBlock','GetBucketPolicyStatus','GetBucketLifecycleConfiguration'])
    for service,name,params in calls:validate_parameters(params,session.get_service_model(service).operation_model(name).input_shape)
