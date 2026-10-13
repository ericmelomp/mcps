"""Static IAM statement signals; no authorization engine, raw policy echo or condition values."""
import json
from urllib.parse import unquote

from .contracts import envelope, bounded
from .eks_cli import CollectionError


def strings(value):
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and len(value)<=500 and all(isinstance(v,str) and len(v)<=2048 for v in value):
        return value
    raise CollectionError('invalid_policy_element')


def document(value):
    if isinstance(value, str):
        if len(value)>32768:
            raise CollectionError('policy_size_limit')
        try:
            value = json.loads(value if value.lstrip().startswith('{') else unquote(value))
        except (ValueError, RecursionError):
            raise CollectionError('invalid_policy_json') from None
    if not isinstance(value,dict) or len(json.dumps(value))>32768:
        raise CollectionError('invalid_policy_document')
    statements = value.get('Statement')
    if isinstance(statements,dict):
        statements=[statements]
    if not isinstance(statements,list) or not statements or len(statements)>100:
        raise CollectionError('invalid_policy_statements')
    return statements


def analyze(value, kind='identity'):
    if kind not in {'identity','trust','resource','scp','rcp','boundary'}:
        raise CollectionError('invalid_policy_kind')
    rows, findings = [], []
    for index, statement in enumerate(document(value)):
        if not isinstance(statement,dict) or statement.get('Effect') not in {'Allow','Deny'}:
            raise CollectionError('invalid_policy_statement')
        if ('Action' in statement)==('NotAction' in statement):
            raise CollectionError('invalid_policy_action')
        if 'Resource' in statement and 'NotResource' in statement:
            raise CollectionError('invalid_policy_resource')
        if kind != 'trust' and not any(k in statement for k in ('Resource','NotResource')):
            raise CollectionError('policy_resource_required')
        actions=strings(statement.get('Action',statement.get('NotAction')))
        resources=strings(statement.get('Resource',statement.get('NotResource',[])))
        conditions=statement.get('Condition',{})
        if not isinstance(conditions,dict) or any(not isinstance(v,dict) for v in conditions.values()):
            raise CollectionError('invalid_policy_condition')
        # Keys can themselves contain user-controlled strings; values and keys are not echoed.
        principal=statement.get('Principal')
        if 'Principal' in statement and 'NotPrincipal' in statement:
            raise CollectionError('invalid_policy_principal')
        if kind in {'trust','resource'} and not any(k in statement for k in ('Principal','NotPrincipal')):
            raise CollectionError('policy_principal_required')
        principal_wildcard = principal=='*'
        federated = False
        if isinstance(principal,dict):
            for key, values in principal.items():
                principals=strings(values)
                principal_wildcard |= '*' in principals
                federated |= key=='Federated' and any('oidc-provider/' in p or p in {'accounts.google.com','cognito-identity.amazonaws.com','www.amazon.com','graph.facebook.com'} for p in principals)
        elif principal is not None and principal!='*':
            raise CollectionError('invalid_policy_principal')
        row={'kind':'policy_statement','statement_index':index,'effect':statement['Effect'],
             'action_count':len(actions),'resource_count':len(resources),'condition_present':bool(conditions),
             'not_action':'NotAction' in statement,'not_resource':'NotResource' in statement,
             'not_principal':'NotPrincipal' in statement,'wildcard_action':any('*' in a for a in actions),
             'wildcard_resource':'*' in resources,'wildcard_principal':principal_wildcard}
        rows.append(row)
        def finding(code,severity='warning'):
            findings.append({'code':code,'severity':severity,'confidence':'confirmed',
                             'evidence':{'statement_index':index,'condition_present':bool(conditions)},
                             'interpretation':'Statement pattern observed; effective permission and exploitability not verified',
                             'recommendations':['Review policy intent, applicable denies and condition constraints']})
        if statement['Effect']=='Allow':
            if 'NotAction' in statement: finding('allow_not_action_requires_review')
            if 'NotResource' in statement: finding('allow_not_resource_requires_review')
            if '*' in actions and '*' in resources: finding('allow_all_actions_resources','high' if not conditions else 'warning')
            elif any(a.endswith(':*') for a in actions) and '*' in resources: finding('allow_service_wildcard_all_resources')
            if principal_wildcard: finding('allow_wildcard_principal','high' if not conditions else 'warning')
            if federated and any(a.lower()=='sts:assumerolewithwebidentity' for a in actions):
                aud = any(str(k).endswith(':aud') for op,values in conditions.items()
                          if op in {'StringEquals','ForAnyValue:StringEquals','ForAllValues:StringEquals'}
                          for k,v in values.items() if isinstance(v,(str,list)) and v and '*' not in strings(v))
                sub = any(str(k).endswith(':sub') for op,values in conditions.items()
                          if op in {'StringEquals','StringLike'} for k,v in values.items()
                          if isinstance(v,(str,list)) and v and '*' not in strings(v))
                if not aud: finding('oidc_audience_constraint_not_observed')
                if not sub: finding('oidc_subject_constraint_not_observed')
        if 'NotPrincipal' in statement: finding('not_principal_requires_context')
    return rows,findings


def query(policy_json,kind='identity'):
    result=envelope()
    try:
        rows,findings=analyze(policy_json,kind)
        result['items']=rows
        result['findings']=findings
        result['summary']={'policy_kind':kind,'statements':len(rows),'finding_count':len(findings),
                           'assessment':'static_patterns_only','effective_authorization_verified':False}
        if findings:result['status']='degraded'
    except Exception as exc:
        result['status']='error';result['coverage']['complete']=False
        result['errors']=[{'code':exc.code if isinstance(exc,CollectionError) else 'policy_analysis_failed'}]
    result['coverage']['exclusions']=['IAM simulation','SCP/RCP inheritance','resource/session policies',
                                     'condition evaluation','external service context','raw documents and condition values']
    return bounded(result)
