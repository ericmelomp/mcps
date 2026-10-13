"""Organization inventory and observed policy inheritance, not effective IAM evaluation."""
from collections import Counter, deque
from .eks_cli import CollectionError
from .ops_runtime import safe_error


def collect(context, result, include_policies=True):
    organization = context.call('organizations', 'describe_organization')['Organization']
    management = organization.get('ManagementAccountId', organization.get('MasterAccountId'))
    result['items'].append({'kind': 'organization', 'resource_id': organization['Id'],
                            'feature_set': organization.get('FeatureSet'), 'management_account_id': management})
    accounts = {}
    for account in context.pages('organizations', 'list_accounts', 'Accounts'):
        item = {'kind': 'organization_account', 'resource_id': account['Id'],
                'name': account.get('Name'), 'state': account.get('State', account.get('Status'))}
        accounts[account['Id']] = item
        result['items'].append(item)
    roots = list(context.pages('organizations', 'list_roots', 'Roots'))
    if not roots:
        raise CollectionError('organization_root_unobserved')
    enabled_types = {p['Type'] for root in roots for p in root.get('PolicyTypes', []) if p.get('Status') == 'ENABLED'}
    transitioning_types = {p['Type'] for root in roots for p in root.get('PolicyTypes', [])
                           if p.get('Status') in {'PENDING_ENABLE','PENDING_DISABLE'}}
    for kind in sorted(transitioning_types):
        result['errors'].append({'code':'policy_type_transitioning','component':kind})
    queue = deque()
    parents, visited, attachments = {}, set(), {}
    for root in roots:
        queue.append(root['Id'])
        result['items'].append({'kind': 'organization_root', 'resource_id': root['Id'],
                                'name': root.get('Name'), 'policy_types': root.get('PolicyTypes', [])})
    while queue:
        parent = queue.popleft()
        if parent in visited:
            raise CollectionError('organization_tree_cycle')
        visited.add(parent)
        if len(visited) > 100:
            raise CollectionError('organization_node_limit')
        for ou in context.pages('organizations', 'list_organizational_units_for_parent', 'OrganizationalUnits', ParentId=parent):
            if ou['Id'] in parents or ou['Id'] in visited:
                raise CollectionError('organization_tree_cycle')
            parents[ou['Id']] = parent
            queue.append(ou['Id'])
            result['items'].append({'kind': 'organization_ou', 'resource_id': ou['Id'],
                                    'name': ou.get('Name'), 'parent_id': parent})
        for child in context.pages('organizations', 'list_children', 'Children', ParentId=parent, ChildType='ACCOUNT'):
            if child['Id'] in parents:
                raise CollectionError('organization_parent_ambiguous')
            parents[child['Id']] = parent
    result['summary'].update(observed_accounts=len(accounts), observed_ous=len(visited)-len(roots),
                             account_states=dict(Counter(a['state'] for a in accounts.values())),
                             enabled_policy_types=sorted(enabled_types),
                             management_account_exempt_from_scp=True)
    if any(account not in parents for account in accounts):
        result['errors'].append({'code': 'account_parent_unobserved', 'component': 'organization_tree'})
    # No content or policy descriptions returned. Each policy attachment is an observation.
    if include_policies:
        for target in sorted(visited | set(accounts)):
            for policy_type in ('SERVICE_CONTROL_POLICY', 'RESOURCE_CONTROL_POLICY'):
                key = (target, policy_type)
                if policy_type in transitioning_types:
                    continue
                attachments[key] = []
                if policy_type not in enabled_types:
                    continue
                try:
                    for policy in context.pages('organizations', 'list_policies_for_target', 'Policies', TargetId=target, Filter=policy_type):
                        attachments[key].append(policy['Id'])
                        if len(result['items']) >= 5000:
                            raise CollectionError('evidence_item_limit')
                        result['items'].append({'kind': 'organization_policy_attachment', 'target_id': target,
                                                'resource_id': policy['Id'], 'policy_type': policy_type,
                                                'name': policy.get('Name'), 'aws_managed': policy.get('AwsManaged')})
                except Exception as exc:
                    attachments.pop(key, None)
                    result['errors'].append({'code': safe_error(exc), 'component': policy_type, 'resource_id': target})
                    if len(result['errors']) >= 20:
                        raise CollectionError('component_error_limit')
    for identifier, account in accounts.items():
        chain, current = [], identifier
        while current:
            chain.append(current)
            current = parents.get(current)
        account['ancestor_ids'] = chain[1:]
        account['policy_inheritance_observed'] = include_policies and identifier in parents and all(
            (node, kind) in attachments for node in chain
            for kind in ('SERVICE_CONTROL_POLICY', 'RESOURCE_CONTROL_POLICY'))
        if include_policies:
            account['policy_ids_by_level'] = [
                {'target_id': node, 'scp_ids': attachments.get((node, 'SERVICE_CONTROL_POLICY')),
                 'rcp_ids': attachments.get((node, 'RESOURCE_CONTROL_POLICY'))} for node in chain]
        if identifier == management:
            account['scp_applies'] = False
        if account.get('state') not in {'ACTIVE', None}:
            result['findings'].append({'code':'account_not_active', 'severity':'info', 'confidence':'confirmed',
                                       'resource_id':identifier, 'evidence':{'state':account['state']},
                                       'recommendations':['Review account lifecycle intent before scheduling workloads']})
    result['summary']['assessment'] = 'observations_only'
    result['coverage'].update(service_scope='Organizations global; region authenticates only',
                              effective_authorization_verified=False,
                              exclusions=['policy document analysis', 'IAM effective permissions', 'Control Tower',
                                          'landing zone baselines', 'resource-specific RCP applicability'])
