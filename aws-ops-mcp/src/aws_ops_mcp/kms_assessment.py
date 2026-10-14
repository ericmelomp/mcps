"""KMS metadata only: no key material, cryptographic calls or policy claims."""
import re
from .eks_cli import CollectionError
from .ops_runtime import safe_error
from .resource_assessments import signal


def validate(key_arn):
    if not isinstance(key_arn, str) or not re.fullmatch(
        r'arn:aws:kms:[a-z0-9-]+:\d{12}:key/(?:mrk-[a-f0-9]{32}|[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12})', key_arn):
        raise CollectionError('invalid_kms_key_arn')


def collect(context, result, key_arn):
    if not key_arn.startswith(f'arn:aws:kms:{context.region}:{context.account_id}:key/'):
        raise CollectionError('kms_scope_mismatch')
    metadata = context.call('kms', 'describe_key', KeyId=key_arn).get('KeyMetadata', {})
    if metadata.get('Arn') != key_arn or metadata.get('AWSAccountId') != context.account_id:
        raise CollectionError('kms_response_scope_mismatch')
    state, manager, origin = (metadata.get(k) for k in ('KeyState', 'KeyManager', 'Origin'))
    spec, usage = metadata.get('KeySpec'), metadata.get('KeyUsage')
    if not all(isinstance(v, str) and v for v in (state, manager, origin, spec, usage)):
        raise CollectionError('kms_metadata_incomplete')
    result['items'].append({'kind': 'kms_key_configuration', 'resource_id': key_arn,
        'state': state, 'manager': manager, 'origin': origin, 'key_spec': spec, 'usage': usage,
        'multi_region': metadata.get('MultiRegion'),
        'multi_region_role': metadata.get('MultiRegionConfiguration', {}).get('MultiRegionKeyType')})
    if state != 'Enabled':
        signal(result, 'kms_key_not_enabled', key_arn, 'high', state=state)
    if origin != 'AWS_KMS':
        signal(result, 'kms_external_material_or_store_observed', key_arn, 'info', origin=origin)
    eligible = (manager == 'CUSTOMER' and origin == 'AWS_KMS' and spec == 'SYMMETRIC_DEFAULT'
                and usage == 'ENCRYPT_DECRYPT' and not metadata.get('CustomKeyStoreId'))
    rotation_observed = False
    if eligible:
        try:
            rotation = context.call('kms', 'get_key_rotation_status', KeyId=key_arn)
            if type(rotation.get('KeyRotationEnabled')) is not bool:
                raise CollectionError('kms_rotation_status_unobserved')
            if rotation.get('KeyId') not in {None, key_arn, key_arn.rsplit('/', 1)[1]}:
                raise CollectionError('kms_rotation_scope_mismatch')
            rotation_observed = True
            result['items'].append({'kind': 'kms_rotation', 'resource_id': key_arn,
                'automatic_rotation_enabled': rotation['KeyRotationEnabled'],
                'rotation_period_days': rotation.get('RotationPeriodInDays')})
            if rotation['KeyRotationEnabled'] is False and state == 'Enabled':
                signal(result, 'kms_automatic_rotation_disabled', key_arn, 'info')
        except Exception as exc:
            result['errors'].append({'code': safe_error(exc), 'component': 'kms_rotation'})
    result['summary'].update(assessment='kms_configuration', rotation_query_applicable=eligible,
        rotation_observed=rotation_observed, effective_access_verified=False, compliance_verified=False)
    result['coverage']['exclusions'] = ['key material/crypto operations', 'raw descriptions/tags',
        'effective key policy/grants/SCP evaluation', 'manual rotation history', 'AWS-managed rotation query',
        'external store availability', 'cryptographic or application acceptance']
