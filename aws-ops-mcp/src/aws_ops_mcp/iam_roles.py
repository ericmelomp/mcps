"""Role policy observations and static diagnostics; never AssumeRole or simulate caller access."""
import re
from .policy_analysis import analyze
from .ops_runtime import safe_error
from .eks_cli import CollectionError


def validate(role_name):
    if not isinstance(role_name,str) or not re.fullmatch(r'[\w+=,.@-]{1,64}',role_name,flags=re.ASCII):
        raise CollectionError('invalid_role_name')


def collect(context,result,role_name):
    validate(role_name)
    role=context.call('iam','get_role',RoleName=role_name)['Role']
    result['items'].append({'kind':'iam_role','resource_id':role['Arn'],
                            'max_session_duration':role.get('MaxSessionDuration'),
                            'permissions_boundary_present':bool(role.get('PermissionsBoundary'))})
    def inspect(doc,source,kind):
        rows,findings=analyze(doc,kind)
        result['items'].extend({**r,'source':source} for r in rows)
        result['findings'].extend({**f,'resource_id':role['Arn'],'source':source} for f in findings)
    inspect(role['AssumeRolePolicyDocument'],'trust','trust')
    for name in context.pages('iam','list_role_policies','PolicyNames',RoleName=role_name):
        try:
            inspect(context.call('iam','get_role_policy',RoleName=role_name,PolicyName=name)['PolicyDocument'],'inline:'+name,'identity')
        except Exception as exc:result['errors'].append({'code':safe_error(exc),'component':'inline_policy'})
        if len(result['items'])>5000:raise CollectionError('evidence_item_limit')
        if len(result['errors'])>=20:raise CollectionError('component_error_limit')
    policy_arns=[]
    for policy in context.pages('iam','list_attached_role_policies','AttachedPolicies',RoleName=role_name):
        policy_arns.append((policy['PolicyArn'],'attached','identity'))
    boundary=role.get('PermissionsBoundary',{}).get('PermissionsBoundaryArn')
    if boundary:policy_arns.append((boundary,'boundary','boundary'))
    for arn,source,kind in policy_arns:
        try:
            version=context.call('iam','get_policy',PolicyArn=arn)['Policy']['DefaultVersionId']
            doc=context.call('iam','get_policy_version',PolicyArn=arn,VersionId=version)['PolicyVersion']['Document']
            result['items'].append({'kind':'iam_policy_version','resource_id':arn,'version':version,'source':source})
            inspect(doc,source+':'+arn,kind)
        except Exception as exc:result['errors'].append({'code':safe_error(exc),'component':source})
        if len(result['items'])>5000:raise CollectionError('evidence_item_limit')
        if len(result['errors'])>=20:raise CollectionError('component_error_limit')
    result['summary'].update(assessment='static_role_patterns_only',effective_authorization_verified=False,
                             attached_policies=len(policy_arns)-(1 if boundary else 0),boundary_present=bool(boundary))
    result['coverage'].update(service_scope='IAM global; region authenticates only',
                              exclusions=['effective permissions','SCP/RCP','session/resource policies','IAM users/groups',
                                          'live AssumeRole test','policy contents and condition values'])
