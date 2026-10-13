"""Bounded read-only SDK execution for new modules; no arbitrary API dispatch."""
import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from botocore.exceptions import ClientError

from .aws import authenticated_session, error_code
from .config import resolve, ConfigurationError
from .eks_cli import CollectionError

OPERATIONS = {
    'organizations': {'describe_organization', 'list_accounts', 'list_roots',
                      'list_organizational_units_for_parent', 'list_children', 'list_policies_for_target'},
    'ce': {'get_cost_and_usage'},
    'ec2': {'describe_vpcs', 'describe_subnets', 'describe_route_tables', 'describe_nat_gateways',
            'describe_internet_gateways', 'describe_vpc_endpoints', 'describe_vpc_peering_connections',
            'describe_security_groups', 'describe_vpc_attribute', 'describe_vpn_connections',
            'describe_transit_gateway_vpc_attachments','describe_instances','describe_volumes'},
    'cloudwatch': {'get_metric_data','describe_alarms'},
    'rds': {'describe_db_instances','describe_db_clusters'},
    'dynamodb': {'describe_table','describe_continuous_backups'},
    'elasticache': {'describe_replication_groups'},
    's3': {'get_bucket_location','get_bucket_encryption','get_bucket_versioning','get_public_access_block',
           'get_bucket_policy_status','get_bucket_lifecycle_configuration'},
    'backup': {'list_recovery_points_by_resource'},
    'guardduty': {'list_detectors','get_detector','list_findings','get_findings'},
    'securityhub': {'get_findings'},
    'cloudtrail': {'lookup_events'},
    'cloudformation': {'describe_stacks','list_stack_resources'},
    'ecs': {'describe_services','describe_task_definition'},
    'lambda': {'get_function_configuration','get_function_concurrency'},
    'sqs': {'get_queue_url','get_queue_attributes'},
    'glue': {'get_job','get_job_runs'},
    'bedrock-agent': {'get_knowledge_base'},
    'sagemaker': {'describe_endpoint','describe_endpoint_config'},
    'directconnect': {'describe_connections'},
    'route53': {'get_hosted_zone', 'list_resource_record_sets'},
    'iam': {'get_role', 'list_role_policies', 'get_role_policy', 'list_attached_role_policies',
            'get_policy', 'get_policy_version'},
}
_audit_lock = threading.Lock()


def audit(record):
    """Opt-in bounded local audit; caller supplies only fixed metadata, no parameters."""
    path = os.environ.get('AWS_OPS_AUDIT_FILE')
    if not path:
        return True
    try:
        target = Path(path).expanduser()
        if not target.is_absolute():
            return False
        with _audit_lock:
            if target.exists() and target.stat().st_size >= 5 * 1024 * 1024:
                return False
            with target.open('a', encoding='utf-8') as stream:
                stream.write(json.dumps(record, ensure_ascii=True) + '\n')
        return True
    except (OSError, ValueError):
        return False


class ReadContext:
    def __init__(self, account, region, factory=authenticated_session, clock=time.monotonic):
        self.account, self.region, self.factory, self.clock = account, region, factory, clock
        self.deadline = clock() + 60
        self.clients = {}
        self.calls = 0
        self.audit_ok = True
        self.account_id = None
        self.sources = []
        self.config = resolve(account, region)
        if region.startswith(('cn-', 'us-gov-')):
            raise CollectionError('partition_not_supported_by_new_modules')
        self.session, self.options = factory(self.config, region)
        self.account_id = self.config.account_id

    def call(self, service, method, **params):
        if method not in OPERATIONS.get(service, set()):
            raise CollectionError('operation_not_permitted')
        if self.clock() >= self.deadline:
            raise CollectionError('deadline_exceeded')
        if self.calls >= 200:
            raise CollectionError('api_call_limit')
        self.calls += 1
        started = self.clock()
        stamp = datetime.now(timezone.utc).isoformat()
        state = 'ok'
        try:
            if service not in self.clients:
                endpoint_region = 'us-east-1' if service in {'organizations','ce','iam','route53'} else self.region
                self.clients[service] = self.session.client(service, region_name=endpoint_region, config=self.options)
            return getattr(self.clients[service], method)(**params)
        except Exception as exc:
            state = error_code(exc)
            raise
        finally:
            source = {'service': service, 'operation': method, 'timestamp': stamp, 'status': state}
            if len(self.sources) < 200:
                self.sources.append(source)
            self.audit_ok = audit({**source, 'account_id': self.account_id,
                                   'authentication_region': self.region,
                                   'duration_ms': int((self.clock() - started) * 1000)}) and self.audit_ok

    def pages(self, service, method, key, **params):
        token_key = 'NextPageToken' if service == 'ce' else 'Marker' if service == 'iam' else 'NextToken'
        seen = set()
        total = 0
        for _ in range(10):
            response = self.call(service, method, **params)
            rows = response.get(key, [])
            for row in rows:
                if total >= 1000:
                    raise CollectionError('object_limit')
                total += 1
                yield row
            token = response.get(token_key)
            if service == 'iam' and not response.get('IsTruncated', False):
                return
            if service == 'iam' and not token:
                raise CollectionError('pagination_token_missing')
            if not token:
                return
            if token in seen:
                raise CollectionError('pagination_cycle')
            seen.add(token)
            params[token_key] = token
        raise CollectionError('page_limit')


def safe_error(exc):
    if isinstance(exc, ConfigurationError):
        return 'configuration_invalid'
    if isinstance(exc, ClientError):
        codes = {'AWSOrganizationsNotInUseException':'organization_not_in_use',
                 'DataUnavailableException':'cost_data_unavailable',
                 'ResourceNotFoundException':'resource_not_found', 'ResourceNotFound':'resource_not_found',
                 'OptInRequired':'region_not_enabled', 'PolicyTypeNotEnabledException':'policy_type_not_enabled',
                 'UnknownEndpoint':'endpoint_unavailable'}
        codes.update({'NoSuchEntity':'resource_not_found','NoSuchBucket':'resource_not_found',
                      'DBInstanceNotFound':'resource_not_found','DBClusterNotFoundFault':'resource_not_found',
                      'ReplicationGroupNotFoundFault':'resource_not_found'})
        code = exc.response.get('Error', {}).get('Code')
        if code in codes:
            return codes[code]
    return exc.code if isinstance(exc, CollectionError) else error_code(exc)
