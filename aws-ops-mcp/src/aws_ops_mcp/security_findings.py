"""Scoped GuardDuty/Security Hub observations, not a clean-security certificate."""
from collections import Counter
from .ops_runtime import safe_error
from .eks_cli import CollectionError


def validate(services,minimum_severity):
    if not isinstance(services,list) or not services or len(services)>2 or len(set(services))!=len(services) or any(s not in {'guardduty','securityhub'} for s in services):
        raise CollectionError('invalid_security_services')
    if type(minimum_severity) is not int or not 0<=minimum_severity<=10:
        raise CollectionError('invalid_guardduty_severity')


def collect(context,result,services,minimum_severity=4):
    observed=Counter()
    def add(row):
        if len(result['items'])>=1000:raise CollectionError('security_finding_limit')
        result['items'].append(row);observed[row['source']]+=1
    for source in services:
        try:
            if source=='guardduty':
                detectors=list(context.pages(source,'list_detectors','DetectorIds'))
                if not detectors:raise CollectionError('guardduty_no_detector_observed')
                if len(detectors)>10:raise CollectionError('guardduty_detector_limit')
                for detector in detectors:
                    state=context.call(source,'get_detector',DetectorId=detector).get('Status')
                    if state!='ENABLED':raise CollectionError('guardduty_detector_not_enabled')
                    criteria={'Criterion':{'accountId':{'Eq':[context.account_id]},'severity':{'Gte':minimum_severity},'service.archived':{'Eq':['false']}}}
                    batch=[]
                    def fetch(ids):
                        raw=context.call(source,'get_findings',DetectorId=detector,FindingIds=ids).get('Findings',[])
                        received=set()
                        for finding in raw:
                            if finding.get('AccountId')!=context.account_id or finding.get('Region')!=context.region:
                                raise CollectionError('finding_scope_mismatch')
                            received.add(finding['Id'])
                            add({'kind':'security_finding','source':source,'resource_id':finding['Arn'],
                                 'finding_id':finding['Id'],'type':finding.get('Type'),'severity_score':finding.get('Severity'),
                                 'updated_at':finding.get('UpdatedAt'),'archived':finding.get('Service',{}).get('Archived')})
                        if received!=set(ids):raise CollectionError('findings_lookup_incomplete')
                    for identifier in context.pages(source,'list_findings','FindingIds',DetectorId=detector,FindingCriteria=criteria):
                        batch.append(identifier)
                        if len(batch)==50:fetch(batch);batch=[]
                    if batch:fetch(batch)
            else:
                filters={'AwsAccountId':[{'Value':context.account_id,'Comparison':'EQUALS'}],
                         'Region':[{'Value':context.region,'Comparison':'EQUALS'}],
                         'RecordState':[{'Value':'ACTIVE','Comparison':'EQUALS'}],
                         'WorkflowStatus':[{'Value':v,'Comparison':'EQUALS'} for v in ('NEW','NOTIFIED')]}
                for finding in context.pages(source,'get_findings','Findings',Filters=filters,MaxResults=100):
                    if finding.get('AwsAccountId')!=context.account_id or finding.get('Region')!=context.region:
                        raise CollectionError('finding_scope_mismatch')
                    add({'kind':'security_finding','source':source,'resource_id':finding['Id'],
                         'severity_label':finding.get('Severity',{}).get('Label'),
                         'workflow':finding.get('Workflow',{}).get('Status'),'record_state':finding.get('RecordState'),
                         'compliance_status':finding.get('Compliance',{}).get('Status'),'updated_at':finding.get('UpdatedAt'),
                         'resource_types':sorted({r.get('Type','unknown') for r in finding.get('Resources',[])})[:10]})
        except Exception as exc:
            result['errors'].append({'code':safe_error(exc),'component':source})
    result['summary'].update(observed_findings=dict(observed),requested_sources=services,
        guardduty_minimum_severity=minimum_severity,assessment='observed_security_findings_only',security_posture_verified=False,
        clean_security_verified=False,actionable_findings=len(result['items']))
    if result['items']:
        result['findings'].append({'code':'security_findings_observed','severity':'warning','confidence':'confirmed',
            'evidence':{'by_source':dict(observed)},'recommendations':['Triage findings using source IDs and business context']})
    result['coverage']['exclusions']=['organization-wide security coverage','resolved/suppressed/archived findings',
                                     'IAM/KMS/configuration scans','raw descriptions/resource details','incident remediation']
