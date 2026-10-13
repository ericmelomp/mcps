from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock
import json
import pytest
import botocore.session
from botocore.validate import validate_parameters
from botocore.exceptions import ClientError
from aws_ops_mcp.platform_ops import Platform
from aws_ops_mcp.evidence import EvidenceStore

ARN = 'arn:aws:ec2:us-east-1:000000000000:instance/i-00000001'


class API:
    def __init__(self):
        self.calls = []
        self.response = {'instanceRecommendations': [{'instanceArn': ARN, 'accountId': '000000000000',
            'finding': 'Overprovisioned', 'lookBackPeriodInDays': 14,
            'lastRefreshTimestamp': datetime.now(timezone.utc)-timedelta(hours=2),
            'instanceName': 'SECRET', 'tags': [{'value': 'SECRET'}],
            'recommendationOptions': [{'instanceType': 'm7g.large', 'rank': 1, 'performanceRisk': 1,
                'platformDifferences': ['Architecture'], 'savingsOpportunity': {'SECRET': 123}}]}]}

    def get_ec2_instance_recommendations(self, **params):
        model = botocore.session.get_session().get_service_model('compute-optimizer')
        validate_parameters(params, model.operation_model('GetEC2InstanceRecommendations').input_shape)
        self.calls.append(params)
        return self.response


def query(api):
    session = MagicMock(); session.client.return_value = api
    return Platform(EvidenceStore(), factory=lambda *args: (session, None)).query(
        'test', 'us-east-1', 'optimizer', instance_ids=['i-00000001'])


def test_targeted_fresh_recommendations_are_not_savings_proof(configured):
    api = API(); result = query(api)
    assert result['coverage']['complete'] and result['summary']['observed_recommendations'] == 1
    assert api.calls[0]['instanceArns'] == [ARN] and api.calls[0]['accountIds'] == ['000000000000']
    assert {'optimizer_memory_metric_unobserved','optimizer_architecture_compatibility_review'} <= {f['code'] for f in result['findings']}
    assert not result['summary']['rightsizing_verified'] and not result['summary']['realized_savings_verified']
    assert 'SECRET' not in json.dumps(result)


def test_missing_recommendation_not_optimized(configured):
    api = API(); api.response = {'instanceRecommendations': []}
    result = query(api)
    assert result['status'] == 'partial' and result['summary']['observed_recommendations'] == 0


def test_stale_memory_evidence_and_error_messages_omitted(configured):
    api = API(); row = api.response['instanceRecommendations'][0]
    row['lastRefreshTimestamp'] -= timedelta(days=8)
    row['utilizationMetrics'] = [{'name': 'Memory','statistic': 'Maximum','value': 50}]
    api.response['errors'] = [{'identifier': ARN,'code': 'SECRET','message': 'SECRET'}]
    result = query(api)
    codes = {f['code'] for f in result['findings']}
    assert result['status'] == 'partial' and 'optimizer_recommendation_stale' in codes
    assert 'optimizer_memory_metric_unobserved' not in codes and 'SECRET' not in json.dumps(result)


@pytest.mark.parametrize('kind', ['account','region','duplicate','future','nan','limit'])
def test_rejects_out_of_scope_malformed_or_duplicate_recommendations(configured, kind):
    api = API(); row = api.response['instanceRecommendations'][0]
    if kind == 'account': row['accountId'] = '111111111111'
    if kind == 'region': row['instanceArn'] = ARN.replace('us-east-1','us-west-2')
    if kind == 'duplicate': api.response['instanceRecommendations'] *= 2
    if kind == 'future': row['lastRefreshTimestamp'] += timedelta(days=2)
    if kind == 'nan': row['lookBackPeriodInDays'] = float('nan')
    if kind == 'limit': api.response['instanceRecommendations'] *= 6
    result = query(api)
    assert not result['coverage']['complete'] and result['status'] in {'partial','error'}


def test_truncation_not_silently_complete(configured):
    api = API(); api.response['nextToken'] = 'more'
    assert query(api)['status'] == 'partial'


@pytest.mark.parametrize('code', ['AccessDeniedException', 'OptInRequiredException', 'ThrottlingException', 'ExpiredToken'])
def test_api_errors_do_not_claim_optimization(configured, code):
    api = API()
    def failure(**params):
        raise ClientError({'Error': {'Code': code,'Message': 'SECRET'}}, 'GetEC2InstanceRecommendations')
    api.get_ec2_instance_recommendations = failure
    result = query(api)
    assert not result['coverage']['complete'] and 'SECRET' not in json.dumps(result)


@pytest.mark.parametrize('ids', [[], ['*'], ['i-00000001','i-00000001']])
def test_invalid_selection_never_authenticates(ids):
    factory = MagicMock()
    result = Platform(EvidenceStore(), factory=factory).query('test','us-east-1','optimizer',instance_ids=ids)
    assert result['status'] == 'error'
    factory.assert_not_called()
