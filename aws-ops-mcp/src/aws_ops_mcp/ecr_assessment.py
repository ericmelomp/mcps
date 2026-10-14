"""One private ECR image digest: existing scan aggregate, no scan creation or image pulls."""
import re
from datetime import datetime, timezone
from .eks_cli import CollectionError
from .ops_runtime import safe_error
from .resource_assessments import signal


def validate(repository_name, image_digest, maximum_age_hours=168):
    if not isinstance(repository_name, str) or len(repository_name) > 256 or not re.fullmatch(
        r'(?:[a-z0-9]+(?:[._-][a-z0-9]+)*/)*[a-z0-9]+(?:[._-][a-z0-9]+)*', repository_name):
        raise CollectionError('invalid_ecr_repository')
    if not isinstance(image_digest, str) or not re.fullmatch(r'sha256:[a-f0-9]{64}', image_digest):
        raise CollectionError('invalid_ecr_image_digest')
    if type(maximum_age_hours) is not int or not 1 <= maximum_age_hours <= 8760:
        raise CollectionError('invalid_ecr_scan_age')


def collect(context, result, repository_name, image_digest, maximum_age_hours=168):
    response = context.call('ecr', 'describe_repositories', registryId=context.account_id,
                            repositoryNames=[repository_name])
    repositories = response.get('repositories', [])
    arn = f'arn:aws:ecr:{context.region}:{context.account_id}:repository/{repository_name}'
    if len(repositories) != 1:
        raise CollectionError('ecr_repository_not_unique')
    repo = repositories[0]
    if (repo.get('repositoryArn') != arn or repo.get('registryId') != context.account_id
            or repo.get('repositoryName') != repository_name):
        raise CollectionError('ecr_repository_scope_mismatch')
    result['items'].append({'kind': 'ecr_repository', 'resource_id': arn,
        'image_tag_mutability': repo.get('imageTagMutability'),
        'encryption_type': repo.get('encryptionConfiguration', {}).get('encryptionType')})
    if repo.get('imageTagMutability') in {'MUTABLE', 'MUTABLE_WITH_EXCLUSION', 'IMMUTABLE_WITH_EXCLUSION'}:
        signal(result, 'ecr_mutable_tags_or_exceptions_configured', arn, 'info')
    observed = False
    try:
        scan = context.call('ecr', 'describe_image_scan_findings', registryId=context.account_id,
            repositoryName=repository_name, imageId={'imageDigest': image_digest}, maxResults=1)
        if (scan.get('registryId') != context.account_id or scan.get('repositoryName') != repository_name
                or scan.get('imageId', {}).get('imageDigest') != image_digest):
            raise CollectionError('ecr_scan_scope_mismatch')
        status = scan.get('imageScanStatus', {}).get('status')
        findings = scan.get('imageScanFindings', {})
        counts = findings.get('findingSeverityCounts')
        if counts is not None and (not isinstance(counts, dict) or any(
            k not in {'INFORMATIONAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'UNDEFINED'}
            or type(v) is not int or v < 0 for k, v in counts.items())):
            raise CollectionError('invalid_ecr_severity_counts')
        stamp = findings.get('imageScanCompletedAt')
        age = None
        if stamp is not None:
            now = datetime.now(timezone.utc)
            if not isinstance(stamp, datetime) or stamp.tzinfo is None or stamp > now:
                raise CollectionError('invalid_ecr_scan_timestamp')
            age = (now - stamp).total_seconds() / 3600
        result['items'].append({'kind': 'ecr_scan_summary', 'resource_id': arn,
            'image_digest': image_digest, 'scan_status': status, 'severity_counts': counts,
            'scan_completed_at': stamp.isoformat() if stamp else None, 'age_hours': age,
            'detail_sample_truncated': bool(scan.get('nextToken'))})
        if status not in {'COMPLETE', 'ACTIVE'}:
            result['errors'].append({'code': 'ecr_scan_not_ready', 'component': 'image_scan'})
        if counts is None or age is None:
            result['errors'].append({'code': 'ecr_scan_evidence_incomplete', 'component': 'image_scan'})
        observed = counts is not None and status in {'COMPLETE', 'ACTIVE'}
        if counts and counts.get('CRITICAL', 0) + counts.get('HIGH', 0) > 0:
            signal(result, 'ecr_high_or_critical_findings_observed', arn, 'high',
                   image_digest=image_digest, high=counts.get('HIGH', 0), critical=counts.get('CRITICAL', 0))
        if age is not None and age > maximum_age_hours:
            signal(result, 'ecr_scan_stale', arn, age_hours=age, maximum_age_hours=maximum_age_hours)
    except Exception as exc:
        result['errors'].append({'code': safe_error(exc), 'component': 'image_scan'})
    result['summary'].update(assessment='ecr_existing_scan_configuration', aggregate_scan_observed=observed,
        maximum_age_hours=maximum_age_hours, image_security_verified=False, workload_image_mapping_verified=False)
    result['coverage']['exclusions'] = ['new scans/Inspector enablement', 'public ECR', 'raw findings/descriptions/tags',
        'finding detail pagination', 'image manifests/layers/pulls', 'signatures/SBOM',
        'running workload image mapping', 'proof of absence of vulnerabilities']
