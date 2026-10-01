import gzip
import io
import json
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from aws_ops_mcp.security import Security, Context, MAX_EXPANDED
from aws_ops_mcp.evidence import EvidenceStore
from aws_ops_mcp.contracts import envelope

ARN = 'arn:aws:wafv2:us-east-1:000000000000:global/webacl/demo/abc'
S3 = 'arn:aws:s3:::aws-waf-logs-test'
START = '2026-09-30T14:00:00Z'
END = '2026-09-30T15:00:00Z'


def setup():
    session = MagicMock()
    clients = {s: MagicMock() for s in ('wafv2', 's3', 'logs', 'ec2')}
    session.client.side_effect = lambda service, **kwargs: clients[service]
    clients['wafv2'].get_logging_configuration.return_value = {'LoggingConfiguration': {'LogDestinationConfigs': [S3]}}
    store = EvidenceStore()
    service = Security(store, lambda *args: (session, None))
    return service, clients, store


def event(identifier='req1', **kw):
    row = {'timestamp': 1790779566323, 'webaclId': ARN, 'action': 'BLOCK', 'terminatingRuleId': 'geo-block',
           'httpRequest': {'requestId': identifier, 'clientIp': '8.8.8.8', 'country': 'US',
              'headers': [{'name': 'Host', 'value': 'example.com'}, {'name': 'Authorization', 'value': 'SECRET'}],
              'args': 'password=SECRET', 'uri': '/cep', 'httpMethod': 'GET'},
           'ruleGroupList': [{'ruleGroupId': 'managed', 'terminatingRule': {'ruleId': 'inner', 'action': 'BLOCK',
               'ruleMatchDetails': [{'matchedData': ['SECRET']}]}}]}
    row.update(kw)
    return row


def search(service, **kwargs):
    params = dict(web_acl_arn=ARN, start_time=START, end_time=END, request_ids=['req1'])
    params.update(kwargs)
    return service.query('test', 'us-east-1', 'logs', **params)


def s3_data(clients, rows):
    payload = gzip.compress(b'\n'.join(json.dumps(r).encode() for r in rows))
    clients['s3'].list_objects_v2.return_value = {'Contents': []}
    clients['s3'].list_objects_v2.side_effect = lambda **kw: {'Contents': [{'Key': 'test.gz', 'Size': len(payload)}]} if '/14/' in kw['Prefix'] else {'Contents': []}
    clients['s3'].get_object.return_value = {'Body': io.BytesIO(payload)}


def test_s3_correlation_and_secret_omission(configured):
    service, clients, store = setup()
    s3_data(clients, [event(), event('other'), event('req1', timestamp=0), event('req1', webaclId='other')])
    result = search(service)
    assert result['status'] == 'ok'
    assert result['summary']['matched_requests'] == 1
    item = result['items'][0]
    assert item['country'] == 'US' and item['terminating_rule'] == 'geo-block'
    assert item['rule_groups'][0]['terminating_rule']['ruleId'] == 'inner'
    assert 'SECRET' not in json.dumps(result)
    assert 'SECRET' not in json.dumps(store.get(result['evidence_id']))
    assert 'WAFLogs/cloudfront/demo/2026/09/30/' in clients['s3'].list_objects_v2.call_args.kwargs['Prefix']


def test_cloudwatch_pagination_and_missing_ids(configured):
    service, clients, _ = setup()
    clients['wafv2'].get_logging_configuration.return_value['LoggingConfiguration']['LogDestinationConfigs'] = [
        'arn:aws:logs:us-east-1:000000000000:log-group:aws-waf-logs-demo']
    clients['logs'].filter_log_events.side_effect = [
        {'events': [], 'nextToken': 'more'}, {'events': [{'message': json.dumps(event()), 'eventId': 'x'}]}]
    result = search(service, request_ids=['req1', 'missing'])
    assert result['status'] == 'ok'
    assert result['summary']['unmatched_request_ids'] == ['missing']
    assert clients['logs'].filter_log_events.call_count == 2


@pytest.mark.parametrize('kwargs,code', [
    ({'start_time': '2026-09-30T14:00:00'}, 'invalid_time_requires_offset'),
    ({'end_time': '2026-10-02T14:00:00Z'}, 'window_must_be_positive_max_24_hours'),
    ({'request_ids': []}, 'request_ids_or_hostname_required'),
    ({'web_acl_arn': ARN.replace('000000000000', '111111111111')}, 'web_acl_account_or_region_mismatch')])
def test_invalid_selector_no_aws(configured, kwargs, code):
    service, clients, _ = setup()
    result = search(service, **kwargs)
    assert result['errors'][0]['code'] == code
    clients['wafv2'].get_logging_configuration.assert_not_called()


def test_access_denied_does_not_leak_error_message(configured):
    service, clients, _ = setup()
    clients['wafv2'].get_logging_configuration.side_effect = ClientError(
        {'Error': {'Code': 'AccessDeniedException', 'Message': 'SECRET'}}, 'GetLoggingConfiguration')
    result = search(service)
    assert result['status'] == 'error'
    assert result['errors'] == [{'code': 'access_denied'}]
    assert 'SECRET' not in str(result)


def test_no_logging_is_explicit(configured):
    service, clients, _ = setup()
    clients['wafv2'].get_logging_configuration.side_effect = ClientError(
        {'Error': {'Code': 'WAFNonexistentItemException'}}, 'GetLoggingConfiguration')
    assert search(service)['errors'][0]['code'] == 'logging_not_configured'


def test_malformed_records_partial(configured):
    service, clients, _ = setup()
    s3_data(clients, [event(), {'wrong': True}])
    result = search(service)
    assert result['status'] == 'partial'
    assert result['coverage']['malformed_records'] == 1


def test_object_limit_preserves_found_evidence(configured):
    service, clients, _ = setup()
    s3_data(clients, [event()])
    clients['s3'].list_objects_v2.side_effect = None
    clients['s3'].list_objects_v2.return_value = {'Contents': [{'Key': 'test.gz', 'Size': 100}, {'Key': 'other.gz', 'Size': 100}]}
    result = search(service, max_objects=1)
    assert result['status'] == 'partial'
    assert result['summary']['matched_requests'] == 1
    assert result['errors'] == [{'code': 'object_limit'}]


def test_repeated_token_not_complete(configured):
    service, clients, _ = setup()
    clients['s3'].list_objects_v2.return_value = {'Contents': [], 'NextContinuationToken': 'same'}
    assert search(service)['errors'] == [{'code': 'pagination_incomplete'}]


def test_waf_rules_redacted_and_ip_sets(configured):
    service, clients, store = setup()
    iparn = ARN.replace('/webacl/demo/abc', '/ipset/office/def')
    clients['wafv2'].get_web_acl.return_value = {'WebACL': {'DefaultAction': {'Allow': {}}, 'Rules': [
        {'Name': 'geo', 'Priority': 20, 'Statement': {'NotStatement': {'Statement': {'GeoMatchStatement': {'CountryCodes': ['BR']}}}}, 'Action': {'Block': {}}},
        {'Name': 'ip', 'Priority': 1, 'Statement': {'IPSetReferenceStatement': {'ARN': iparn}}, 'Action': {'Count': {}}},
        {'Name': 'secret', 'Priority': 30, 'Statement': {'ByteMatchStatement': {'SearchString': b'SECRET'}},
         'Action': {'Allow': {'CustomRequestHandling': {'InsertHeaders': [{'Name': 'x', 'Value': 'SECRET'}]}}}}]}}
    clients['wafv2'].get_ip_set.return_value = {'IPSet': {'IPAddressVersion': 'IPV4', 'Addresses': ['8.8.8.8/32']}}
    result = service.query('test', 'us-east-1', 'inspect', web_acl_arn=ARN)
    assert result['status'] == 'ok'
    assert [x['Name'] for x in result['items'] if x['kind'] == 'rule'] == ['ip', 'geo', 'secret']
    assert any(x['kind'] == 'ip_set_address' for x in result['items'])
    assert 'SECRET' not in str(store.get(result['evidence_id']))


def test_ip_lookup_both_apis_and_pagination(configured):
    service, clients, _ = setup()
    clients['ec2'].describe_nat_gateways.side_effect = [{'NatGateways': [], 'NextToken': 'next'},
        {'NatGateways': [{'NatGatewayId': 'nat-test', 'State': 'available', 'NatGatewayAddresses': [{'PublicIp': '8.8.8.8'}]}]}]
    clients['ec2'].describe_addresses.return_value = {'Addresses': [{'PublicIp': '8.8.8.8', 'AllocationId': 'eip-test'}]}
    result = service.query('test', 'us-east-1', 'ip', public_ip='8.8.8.8')
    assert result['status'] == 'ok' and len(result['items']) == 2
    assert clients['ec2'].describe_nat_gateways.call_args.kwargs['NextToken'] == 'next'


def test_private_ip_rejected(configured):
    service, clients, _ = setup()
    assert service.query('test', 'us-east-1', 'ip', public_ip='10.0.0.1')['errors'][0]['code'] == 'public_ipv4_required'
    clients['ec2'].describe_addresses.assert_not_called()


def test_gzip_expansion_bounded(configured):
    service, clients, _ = setup()
    payload = gzip.compress(b'x'*(MAX_EXPANDED+1))
    clients['s3'].list_objects_v2.return_value = {'Contents': [{'Key': 'test.gz', 'Size': len(payload)}]}
    clients['s3'].get_object.return_value = {'Body': io.BytesIO(payload)}
    assert search(service)['errors'][0]['code'] == 'expanded_object_limit'

def test_empty_ip_lookup_is_not_ownership_proof(configured):
    service, clients, _ = setup()
    clients['ec2'].describe_nat_gateways.return_value = {'NatGateways': []}
    clients['ec2'].describe_addresses.return_value = {'Addresses': []}
    result = service.query('test', 'us-east-1', 'ip', public_ip='8.8.8.8')
    assert result['status'] == 'ok' and result['items'] == []
    assert 'does not establish ownership' in result['summary']['interpretation']


def test_ip_one_api_denied_preserves_other_evidence(configured):
    service, clients, _ = setup()
    clients['ec2'].describe_nat_gateways.side_effect = ClientError({'Error': {'Code': 'AccessDenied'}}, 'DescribeNatGateways')
    clients['ec2'].describe_addresses.return_value = {'Addresses': [{'PublicIp': '8.8.8.8'}]}
    result = service.query('test', 'us-east-1', 'ip', public_ip='8.8.8.8')
    assert result['status'] == 'partial' and result['items'][0]['kind'] == 'elastic_ip'


def test_deadline_is_explicit():
    from aws_ops_mcp.eks_cli import CollectionError
    c = Context(MagicMock(), None, envelope('test', 'us-east-1'))
    c.deadline = 0
    with pytest.raises(CollectionError, match='deadline_exceeded'):
        c.call('ec2', 'describe_addresses')
    c.session.client.assert_not_called()


def test_firehose_is_explicitly_unsupported(configured):
    service, clients, _ = setup()
    clients['wafv2'].get_logging_configuration.return_value['LoggingConfiguration']['LogDestinationConfigs'] = [
        'arn:aws:firehose:us-east-1:000000000000:deliverystream/example']
    assert search(service)['errors'][0]['code'] == 'logging_destination_unsupported'


def test_timezone_filters_and_exclusive_end(configured):
    service, clients, _ = setup()
    stamp = event()['timestamp']
    s3_data(clients, [event(), event('at-end', timestamp=1790780400000)])
    result = search(service, start_time='2026-09-30T11:00:00-03:00',
                    end_time='2026-09-30T12:00:00-03:00', request_ids=['req1', 'at-end'])
    assert [i['timestamp'] for i in result['items']] == [stamp]
    assert result['summary']['unmatched_request_ids'] == ['at-end']


def test_s3_missing_continuation_token_is_partial(configured):
    service, clients, _ = setup()
    clients['s3'].list_objects_v2.return_value = {'Contents': [], 'IsTruncated': True}
    assert search(service)['errors'][0]['code'] == 'pagination_incomplete'
