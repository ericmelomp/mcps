"""Explicit Route53 zone/record inspection, not a runtime resolver or traffic test."""
import re
from .eks_cli import CollectionError


def validate(hosted_zone_id,record_name):
    if not isinstance(hosted_zone_id,str) or not re.fullmatch(r'Z[A-Z0-9]{1,31}',hosted_zone_id):
        raise CollectionError('invalid_hosted_zone_id')
    if not isinstance(record_name,str) or len(record_name)>253 or not re.fullmatch(r'(?:[a-zA-Z0-9_*-]+\.)+[a-zA-Z0-9_-]+\.?',record_name):
        raise CollectionError('invalid_dns_name')


def collect(context,result,hosted_zone_id,record_name):
    validate(hosted_zone_id,record_name)
    zone=context.call('route53','get_hosted_zone',Id=hosted_zone_id)
    name=record_name.lower().rstrip('.')+'.';zone_name=zone['HostedZone']['Name'].lower()
    if name!=zone_name and not name.endswith('.'+zone_name):raise CollectionError('record_outside_hosted_zone')
    result['items'].append({'kind':'dns_zone','resource_id':hosted_zone_id,'name':zone_name,
                            'private':zone['HostedZone'].get('Config',{}).get('PrivateZone',False),
                            'vpcs':zone.get('VPCs',[]),'name_servers':zone.get('DelegationSet',{}).get('NameServers',[])})
    params={'HostedZoneId':hosted_zone_id,'StartRecordName':name,'MaxItems':'100'}
    seen=set();matched=0;types=set()
    for _ in range(10):
        page=context.call('route53','list_resource_record_sets',**params)
        passed=False
        for record in page.get('ResourceRecordSets',[]):
            if record['Name'].lower()!=name:
                passed=True;continue
            if matched>=100:raise CollectionError('dns_record_limit')
            matched+=1;types.add(record['Type'])
            # TXT can hold arbitrary secrets. Return counts, not values; keep routing metadata.
            values=record.get('ResourceRecords',[])
            item={'kind':'dns_record','name':name,'type':record['Type'],'ttl':record.get('TTL'),
                  'value_count':len(values),'values_omitted':record['Type'] not in {'A','AAAA','CNAME','NS','MX'},
                  'health_check_present':bool(record.get('HealthCheckId')),
                  'routing':{k:record[k] for k in ('Weight','Region','Failover','MultiValueAnswer') if k in record}}
            if not item['values_omitted']:item['values']=[v['Value'] for v in values][:20]
            if len(values)>20:result['errors'].append({'code':'dns_value_limit','component':'records'})
            if 'AliasTarget' in record:item['alias']={k:record['AliasTarget'][k] for k in ('DNSName','HostedZoneId','EvaluateTargetHealth') if k in record['AliasTarget']}
            result['items'].append(item)
            if name==zone_name and record['Type']=='CNAME':
                result['findings'].append({'code':'apex_cname_observed','severity':'warning','confidence':'confirmed',
                    'resource_id':hosted_zone_id,'evidence':{'name':name},'recommendations':['Use a supported apex alias design']})
        if passed or not page.get('IsTruncated'):break
        token=tuple(page.get(k) for k in ('NextRecordName','NextRecordType','NextRecordIdentifier'))
        if not token[0] or not token[1] or token in seen:raise CollectionError('dns_pagination_invalid')
        seen.add(token)
        params.update(StartRecordName=token[0],StartRecordType=token[1])
        if token[2]:params['StartRecordIdentifier']=token[2]
        else:params.pop('StartRecordIdentifier',None)
    else:raise CollectionError('dns_page_limit')
    result['summary'].update(observed_matching_records=matched,record_types=sorted(types),
                             assessment='zone_configuration_only' if matched else 'no_exact_record_observed',
                             resolution_verified=False)
    result['coverage'].update(service_scope='Route53 global explicit zone',exclusions=['public delegation verification',
        'runtime DNS resolution','Resolver endpoints/rules','wildcard record synthesis','health check status','TXT/SPF/DKIM contents'])
