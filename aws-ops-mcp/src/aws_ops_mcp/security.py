"""Bounded, read-only WAF and public IP evidence using authenticated SDK sessions."""

import gzip
import io
import ipaddress
import json
import re
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from .aws import authenticated_session, error_code
from .config import ConfigurationError, resolve
from .contracts import bounded, envelope
from .eks_cli import CollectionError

ACL = re.compile(r'^arn:(aws(?:-us-gov|-cn)?):wafv2:([a-z0-9-]+):(\d{12}):(global|regional)/webacl/([\w-]+)/([\w-]+)$')
MAX_OBJECT = 4 * 1024 * 1024
MAX_EXPANDED = 16 * 1024 * 1024


def utc(value):
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            raise ValueError()
        return parsed.astimezone(timezone.utc)
    except (ValueError, TypeError):
        raise CollectionError('invalid_time_requires_offset') from None


def rule_view(value):
    """Preserve rule structure while omitting arbitrary match/header/body contents."""
    if isinstance(value, list):
        return [rule_view(v) for v in value]
    if isinstance(value, dict):
        return {k: rule_view(v) for k, v in value.items() if k not in {
            'SearchString', 'RegexString', 'CustomRequestHandling', 'CustomResponse',
            'CustomResponseBodies', 'Description', 'LockToken', 'ResponseMetadata'}}
    if isinstance(value, bytes):
        return '[omitted]'
    return value


class Security:
    def __init__(self, store, factory=authenticated_session):
        self.store, self.factory = store, factory

    def query(self, account, region, kind, **target):
        result = envelope(account, region)
        result['items'] = []
        result['coverage'].update(scope='One configured account and region; observational evidence only')
        try:
            config = resolve(account, region)
            # Validate selectors before authenticating or calling AWS.
            if kind != 'ip':
                match = ACL.fullmatch(target.get('web_acl_arn', ''))
                if not match or match[3] != config.account_id or match[2] != region:
                    raise CollectionError('web_acl_account_or_region_mismatch')
                if match[4] == 'global' and region != 'us-east-1':
                    raise CollectionError('cloudfront_requires_us_east_1')
                target['acl_parts'] = match.groups()
            if kind == 'logs':
                start, end = utc(target['start_time']), utc(target['end_time'])
                if not timedelta(0) < end - start <= timedelta(days=1):
                    raise CollectionError('window_must_be_positive_max_24_hours')
                target.update(start=start, end=end)
                if not target.get('request_ids') and not target.get('hostname'):
                    raise CollectionError('request_ids_or_hostname_required')
            if kind == 'ip':
                try:
                    address = ipaddress.ip_address(target['public_ip'])
                    if address.version != 4 or not address.is_global:
                        raise ValueError()
                except ValueError:
                    raise CollectionError('public_ipv4_required') from None
            session, options = self.factory(config, region)
            context = Context(session, options, result)
            getattr(self, kind)(context, **target)
        except ConfigurationError:
            result['errors'].append({'code': 'configuration_invalid'})
        except Exception as exc:
            result['errors'].append({'code': exc.code if isinstance(exc, CollectionError) else error_code(exc)})
        if result['errors']:
            result['coverage']['complete'] = False
            result['status'] = 'partial' if result['items'] else 'error'
        result['summary']['returned_items'] = len(result['items'])
        if result['items']:
            key = self.store.put(account, region, result['items'], result['coverage'])
            if key:
                result['evidence_id'] = key
            else:
                result['coverage']['evidence_unavailable'] = True
        return bounded(result)

    def inspect(self, c, web_acl_arn, acl_parts):
        _, _, _, scope, name, identifier = acl_parts
        scope = 'CLOUDFRONT' if scope == 'global' else 'REGIONAL'
        acl = c.call('wafv2', 'get_web_acl', Name=name, Id=identifier, Scope=scope)['WebACL']
        c.add({'kind': 'web_acl', 'arn': web_acl_arn, 'default_action': rule_view(acl['DefaultAction'])})
        refs = set()
        def references(value):
            if isinstance(value, dict):
                for key, val in value.items():
                    if key == 'IPSetReferenceStatement':
                        refs.add(val['ARN'])
                    references(val)
            elif isinstance(value, list):
                for val in value:
                    references(val)
        for rule in sorted(acl.get('Rules', []), key=lambda x: x['Priority']):
            c.add({'kind': 'rule', **rule_view(rule)})
            references(rule)
        c.result['coverage']['exclusions'] = ['Referenced rule group contents and managed rule definitions are not expanded',
                                              'Match strings, custom headers and response bodies are omitted']
        for arn in sorted(refs):
            try:
                parts = arn.split(':', 5)
                resource = parts[5].split('/')
                if parts[4] != acl_parts[2] or parts[3] != acl_parts[1] or resource[1] != 'ipset':
                    raise CollectionError('ip_set_outside_scope')
                data = c.call('wafv2', 'get_ip_set', Name=resource[2], Id=resource[3], Scope=scope)['IPSet']
                c.add({'kind': 'ip_set', 'arn': arn, 'ip_version': data['IPAddressVersion'],
                       'address_count': len(data.get('Addresses', []))})
                for address in data.get('Addresses', []):
                    c.add({'kind': 'ip_set_address', 'arn': arn, 'cidr': address})
            except Exception as exc:
                c.error(exc)
        logging = c.logging(web_acl_arn)
        c.add({'kind': 'logging', 'configuration': rule_view(logging)})

    def ip(self, c, public_ip):
        c.result['coverage']['exclusions'] = ['Other accounts/regions, proxies, external egress and IPv6',
                                              'Association does not prove a workload uses this egress']
        for operation, key, filters in (
            ('describe_nat_gateways', 'NatGateways', [{'Name': 'nat-gateway-address.public-ip', 'Values': [public_ip]}]),
            ('describe_addresses', 'Addresses', [{'Name': 'public-ip', 'Values': [public_ip]}])):
            try:
                for page in c.pages('ec2', operation, Filter=filters) if key == 'NatGateways' else [c.call('ec2', operation, Filters=filters)]:
                    for item in page.get(key, []):
                        if key == 'NatGateways':
                            c.add({'kind': 'nat_gateway', 'id': item['NatGatewayId'], 'vpc_id': item.get('VpcId'),
                                   'subnet_id': item.get('SubnetId'), 'state': item.get('State'),
                                   'addresses': [{k: a.get(k) for k in ('PublicIp', 'PrivateIp', 'AllocationId', 'NetworkInterfaceId')}
                                                 for a in item.get('NatGatewayAddresses', [])]})
                        else:
                            c.add({'kind': 'elastic_ip', **{k: item.get(k) for k in (
                                'PublicIp', 'AllocationId', 'AssociationId', 'InstanceId', 'NetworkInterfaceId', 'PrivateIp')}})
            except Exception as exc:
                c.error(exc)
        c.result['summary']['interpretation'] = 'Matches only in queried account/region; no match does not establish ownership'

    def logs(self, c, web_acl_arn, acl_parts, start_time, end_time, start, end,
             request_ids=None, hostname='', path='', max_objects=1000):
        ids = set(request_ids or [])
        found = set()
        c.result['coverage'].update(start_time=start.isoformat(), end_time_exclusive=end.isoformat(),
            scope='Available retained logs at current configured destination; not proof of all historical traffic',
            objects_scanned=0, records_scanned=0, malformed_records=0)
        logging = c.logging(web_acl_arn)
        c.result['summary']['logging_filter_present'] = bool(logging.get('LoggingFilter'))
        destinations = logging.get('LogDestinationConfigs', [])
        if not destinations:
            raise CollectionError('logging_not_configured')
        def consume(raw, source):
            c.check()
            c.result['coverage']['records_scanned'] += 1
            if c.result['coverage']['records_scanned'] > 100000:
                raise CollectionError('record_limit')
            try:
                row = json.loads(raw)
                request = row['httpRequest']
                stamp = row['timestamp']
                if row.get('webaclId') != web_acl_arn or not start.timestamp()*1000 <= stamp < end.timestamp()*1000:
                    return
                request_id = request.get('requestId', '')
                host = next((h.get('value', '') for h in request.get('headers', []) if h.get('name', '').lower() == 'host'), '')
                if ids and request_id not in ids:
                    return
                if hostname and host.lower().rstrip('.') != hostname.lower().rstrip('.'):
                    return
                if path and request.get('uri') != path:
                    return
                item = {'kind': 'waf_request', 'timestamp': stamp, 'request_id': request_id,
                    'client_ip': request.get('clientIp'), 'country': request.get('country'),
                    'host': host, 'uri': request.get('uri'), 'method': request.get('httpMethod'),
                    'action': row.get('action'), 'terminating_rule': row.get('terminatingRuleId'),
                    'terminating_rule_type': row.get('terminatingRuleType'),
                    'source': source, 'rule_groups': [
                        {'id': g.get('ruleGroupId'), 'terminating_rule': {
                            k: g['terminatingRule'].get(k) for k in ('ruleId', 'action')}}
                        for g in row.get('ruleGroupList', []) if g.get('terminatingRule')]}
                c.add(item)
                found.add(request_id)
            except (ValueError, KeyError, TypeError, AttributeError):
                c.result['coverage']['malformed_records'] += 1
        try:
            for destination in destinations:
                if ':s3:::' in destination:
                    self.s3(c, destination, acl_parts, start, end, consume, max_objects)
                elif ':logs:' in destination:
                    self.cloudwatch(c, destination, start, end, consume)
                else:
                    raise CollectionError('logging_destination_unsupported')
        finally:
            c.result['summary'].update(matched_requests=len(found), unmatched_request_ids=sorted(ids-found))
            if c.result['coverage']['malformed_records']:
                c.result['errors'].append({'code': 'malformed_log_records'})

    def cloudwatch(self, c, destination, start, end, consume):
        parts = destination.split(':', 5)
        if parts[3] != c.region or not parts[5].startswith('log-group:'):
            raise CollectionError('unsupported_log_group_arn')
        group = parts[5][len('log-group:'):].removesuffix(':*')
        for page in c.pages('logs', 'filter_log_events', token_key='nextToken', output_token='nextToken',
                           logGroupName=group, startTime=int(start.timestamp()*1000), endTime=int(end.timestamp()*1000), limit=1000):
            for event in page.get('events', []):
                consume(event['message'], {'log_group': group, 'event_id': event.get('eventId')})

    def s3(self, c, destination, acl_parts, start, end, consume, max_objects):
        location = destination.split(':::', 1)[1]
        bucket, _, prefix = location.partition('/')
        _, region, account, scope, name, _ = acl_parts
        root = (prefix.rstrip('/') + '/' if prefix else '') + f'AWSLogs/{account}/WAFLogs/{"cloudfront" if scope == "global" else region}/{name}/'
        # Include adjacent hours for five-minute delivery windows at boundaries.
        day = start.replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)
        stop = end + timedelta(hours=1)
        c.result['coverage']['s3_partition_padding_hours'] = 1
        total_bytes = 0
        while day < stop:
            for page in c.pages('s3', 'list_objects_v2', token_key='ContinuationToken', output_token='NextContinuationToken',
                               Bucket=bucket, Prefix=root+day.strftime('%Y/%m/%d/%H/'), MaxKeys=1000):
                for obj in page.get('Contents', []):
                    c.check()
                    if not obj['Key'].endswith('.gz'):
                        continue
                    if c.result['coverage']['objects_scanned'] >= max_objects:
                        raise CollectionError('object_limit')
                    if obj['Size'] > MAX_OBJECT:
                        raise CollectionError('object_size_limit')
                    total_bytes += obj['Size']
                    if total_bytes > 32*1024*1024:
                        raise CollectionError('compressed_byte_limit')
                    try:
                        response = c.call('s3', 'get_object', Bucket=bucket, Key=obj['Key'])
                        body = response['Body']
                        try:
                            compressed = body.read(MAX_OBJECT+1)
                        finally:
                            body.close()
                        if len(compressed) > MAX_OBJECT:
                            raise CollectionError('object_size_limit')
                        with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
                            data = stream.read(MAX_EXPANDED+1)
                        if len(data) > MAX_EXPANDED:
                            raise CollectionError('expanded_object_limit')
                        c.result['coverage']['objects_scanned'] += 1
                        for line in data.splitlines():
                            consume(line, {'bucket': bucket, 'key': obj['Key']})
                    except (gzip.BadGzipFile, EOFError):
                        c.error(CollectionError('malformed_gzip_object'))
            day += timedelta(hours=1)


class Context:
    def __init__(self, session, options, result):
        self.session, self.options, self.result = session, options, result
        self.region = result['region']
        self.deadline = time.monotonic()+45
        self.clients = {}

    def check(self):
        if time.monotonic() >= self.deadline:
            raise CollectionError('deadline_exceeded')

    def call(self, service, operation, **kwargs):
        self.check()
        if service not in self.clients:
            self.clients[service] = self.session.client(service, region_name=self.region, config=self.options)
        return getattr(self.clients[service], operation)(**kwargs)

    def add(self, item):
        if len(self.result['items']) >= 1000:
            raise CollectionError('item_limit')
        # Avoid a single rule exhausting evidence pagination.
        if len(json.dumps(item)) > 12000:
            raise CollectionError('item_size_limit')
        self.result['items'].append(item)

    def error(self, exc):
        entry = {'code': exc.code if isinstance(exc, CollectionError) else error_code(exc)}
        if entry not in self.result['errors']:
            self.result['errors'].append(entry)

    def logging(self, arn):
        try:
            return self.call('wafv2', 'get_logging_configuration', ResourceArn=arn)['LoggingConfiguration']
        except ClientError as exc:
            if exc.response['Error']['Code'] == 'WAFNonexistentItemException':
                return {}
            raise

    def pages(self, service, operation, token_key='NextToken', output_token='NextToken', **params):
        seen = set()
        for _ in range(100):
            page = self.call(service, operation, **params)
            yield page
            token = page.get(output_token)
            if not token:
                if page.get('IsTruncated'):
                    raise CollectionError('pagination_incomplete')
                return
            if token in seen:
                raise CollectionError('pagination_incomplete')
            seen.add(token)
            params[token_key] = token
        raise CollectionError('page_limit')
