import json
from functools import lru_cache
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock
import pytest
import botocore.session
from botocore.validate import validate_parameters
from botocore.exceptions import ClientError
from aws_ops_mcp.platform_ops import Platform
from aws_ops_mcp.evidence import EvidenceStore
from aws_ops_mcp.ops_runtime import ReadContext
from aws_ops_mcp.eks_cli import CollectionError

KEY = 'arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-000000000000'
REPO = 'arn:aws:ecr:us-east-1:000000000000:repository/demo'
DIGEST = 'sha256:' + '0'*64


@lru_cache(maxsize=2)
def service_model(service):
    return botocore.session.get_session().get_service_model(service)


class API:
    def __init__(self):
        self.calls = []
        self.key = {'Arn':KEY,'AWSAccountId':'000000000000','KeyState':'Enabled',
            'KeyManager':'CUSTOMER','Origin':'AWS_KMS','KeySpec':'SYMMETRIC_DEFAULT',
            'KeyUsage':'ENCRYPT_DECRYPT','Description':'SECRET'}
        self.rotation = {'KeyRotationEnabled':False, 'KeyId':KEY}
        self.repo = {'repositoryArn':REPO,'registryId':'000000000000','repositoryName':'demo',
            'imageTagMutability':'IMMUTABLE','repositoryUri':'SECRET'}
        self.scan = {'registryId':'000000000000','repositoryName':'demo','imageId':{'imageDigest':DIGEST},
            'imageScanStatus':{'status':'COMPLETE','description':'SECRET'},
            'imageScanFindings':{'imageScanCompletedAt':datetime.now(timezone.utc)-timedelta(hours=1),
                'findingSeverityCounts':{'HIGH':2},'findings':[{'description':'SECRET'}],
                'enhancedFindings':[{'description':'SECRET'}]}}

    def check(self, service, method, params):
        model = service_model(service)
        validate_parameters(params, model.operation_model(method).input_shape)
        self.calls.append((service,method,params))

    def describe_key(self, **params):
        self.check('kms','DescribeKey',params); return {'KeyMetadata':self.key}

    def get_key_rotation_status(self, **params):
        self.check('kms','GetKeyRotationStatus',params); return self.rotation

    def describe_repositories(self, **params):
        self.check('ecr','DescribeRepositories',params); return {'repositories':[self.repo]}

    def describe_image_scan_findings(self, **params):
        self.check('ecr','DescribeImageScanFindings',params); return self.scan


def query(api, kind='kms', **params):
    session = MagicMock(); session.client.return_value = api
    platform = Platform(EvidenceStore(), factory=lambda *a: (session,None))
    default = {'key_arn':KEY} if kind == 'kms' else {'repository_name':'demo','image_digest':DIGEST}
    default.update(params)
    result = platform.query('test','us-east-1',kind,**default)
    rows = platform.store.get(result['evidence_id'])['items'] if result.get('evidence_id') else []
    return result, rows


def codes(result):
    return {f['code'] for f in result['findings']}


def test_kms_rotation_state_and_secret_omission(configured):
    api = API(); result, rows = query(api)
    assert result['coverage']['complete'] and result['summary']['rotation_observed']
    assert 'kms_automatic_rotation_disabled' in codes(result)
    assert not result['summary']['effective_access_verified'] and 'SECRET' not in json.dumps(rows)
    api.key['KeyState'] = 'PendingDeletion'
    assert 'kms_key_not_enabled' in codes(query(api)[0])


@pytest.mark.parametrize('field,value', [('KeyManager','AWS'),('Origin','EXTERNAL'),
    ('KeySpec','RSA_2048'),('KeyUsage','SIGN_VERIFY'),('CustomKeyStoreId','demo')])
def test_kms_rotation_not_queried_for_inapplicable_keys(configured, field, value):
    api = API(); api.key[field] = value
    result, _ = query(api)
    assert not result['summary']['rotation_query_applicable']
    assert not any(method == 'GetKeyRotationStatus' for _,method,_ in api.calls)
    assert 'kms_automatic_rotation_disabled' not in codes(result)


def test_kms_foreign_input_is_rejected_before_api(configured):
    api = API(); result,_ = query(api,key_arn=KEY.replace('000000000000:key','111111111111:key'))
    assert not result['coverage']['complete'] and api.calls == []


@pytest.mark.parametrize('field,value', [('Arn',KEY.replace('us-east-1','us-west-2')),
    ('AWSAccountId','111111111111'),('KeyState',None)])
def test_kms_invalid_response_rejected_before_rotation(configured, field, value):
    api = API(); api.key[field] = value; result,_ = query(api)
    assert not result['coverage']['complete']
    assert not any(method == 'GetKeyRotationStatus' for _,method,_ in api.calls)


def test_kms_rotation_denied_keeps_metadata(configured):
    api = API()
    def failure(**p):
        raise ClientError({'Error':{'Code':'AccessDeniedException','Message':'SECRET'}},'GetKeyRotationStatus')
    api.get_key_rotation_status = failure; result, rows = query(api)
    assert result['status'] == 'partial' and not result['summary']['rotation_observed']
    assert any(r['kind']=='kms_key_configuration' for r in rows) and 'SECRET' not in json.dumps(rows)


def test_ecr_aggregate_high_findings_and_no_raw_data(configured):
    api = API(); api.scan['nextToken'] = 'more'; result, rows = query(api,'ecr')
    assert result['coverage']['complete'] and result['summary']['aggregate_scan_observed']
    assert 'ecr_high_or_critical_findings_observed' in codes(result)
    assert not result['summary']['image_security_verified'] and 'SECRET' not in json.dumps(rows)
    scan = next(r for r in rows if r['kind']=='ecr_scan_summary')
    assert scan['severity_counts']=={'HIGH':2} and scan['detail_sample_truncated']
    assert api.calls[-1][2]['registryId']=='000000000000' and api.calls[-1][2]['maxResults']==1


@pytest.mark.parametrize('status', ['IN_PROGRESS','FAILED','UNSUPPORTED_IMAGE','PENDING',
    'SCAN_ELIGIBILITY_EXPIRED','FINDINGS_UNAVAILABLE','LIMIT_EXCEEDED','IMAGE_ARCHIVED'])
def test_ecr_not_ready_is_partial_even_with_zero_counts(configured,status):
    api = API(); api.scan['imageScanStatus']['status']=status
    api.scan['imageScanFindings']['findingSeverityCounts']={}
    result,_ = query(api,'ecr')
    assert result['status']=='partial' and not result['summary']['aggregate_scan_observed']


def test_ecr_active_scan_missing_time_is_partial(configured):
    api = API(); api.scan['imageScanStatus']['status']='ACTIVE'
    del api.scan['imageScanFindings']['imageScanCompletedAt']
    assert query(api,'ecr')[0]['status']=='partial'


def test_ecr_stale_scan_and_mutable_tag_signal(configured):
    api = API(); api.repo['imageTagMutability']='IMMUTABLE_WITH_EXCLUSION'
    api.scan['imageScanFindings']['imageScanCompletedAt']-=timedelta(days=8)
    assert {'ecr_scan_stale','ecr_mutable_tags_or_exceptions_configured'} <= codes(query(api,'ecr')[0])


@pytest.mark.parametrize('kind', ['repo_account','scan_account','digest','negative','missing_counts','future'])
def test_ecr_malformed_scope_or_counts_are_not_security_proof(configured,kind):
    api = API()
    if kind=='repo_account':api.repo['registryId']='111111111111'
    if kind=='scan_account':api.scan['registryId']='111111111111'
    if kind=='digest':api.scan['imageId']['imageDigest']='sha256:'+'1'*64
    if kind=='negative':api.scan['imageScanFindings']['findingSeverityCounts']={'HIGH':-1}
    if kind=='missing_counts':del api.scan['imageScanFindings']['findingSeverityCounts']
    if kind=='future':api.scan['imageScanFindings']['imageScanCompletedAt']+=timedelta(days=2)
    result,_ = query(api,'ecr')
    assert not result['coverage']['complete'] and not result['summary'].get('image_security_verified',False)


@pytest.mark.parametrize('code', ['ScanNotFoundException','AccessDeniedException','ThrottlingException','ExpiredToken'])
def test_ecr_scan_errors_keep_repo_and_omit_error_messages(configured,code):
    api = API()
    def failure(**p):
        raise ClientError({'Error':{'Code':code,'Message':'SECRET'}},'DescribeImageScanFindings')
    api.describe_image_scan_findings=failure; result,rows = query(api,'ecr')
    assert result['status']=='partial' and any(r['kind']=='ecr_repository' for r in rows)
    assert 'SECRET' not in json.dumps(rows)


@pytest.mark.parametrize('kind,params', [('kms',{'key_arn':'alias/demo'}),
    ('ecr',{'repository_name':'../demo','image_digest':DIGEST}),
    ('ecr',{'repository_name':'demo','image_digest':'latest'})])
def test_invalid_selection_does_not_authenticate(kind, params):
    factory = MagicMock()
    result=Platform(EvidenceStore(),factory=factory).query('test','us-east-1',kind,**params)
    assert result['status']=='error'; factory.assert_not_called()


def test_kms_crypto_and_ecr_mutations_are_not_permitted(configured):
    session = MagicMock()
    context=ReadContext('test','us-east-1',factory=lambda *a:(session,None))
    for service,method in [('kms','decrypt'),('kms','get_key_policy'),('ecr','start_image_scan'),('ecr','batch_get_image')]:
        with pytest.raises(CollectionError,match='operation_not_permitted'):context.call(service,method)
    session.client.assert_not_called()
