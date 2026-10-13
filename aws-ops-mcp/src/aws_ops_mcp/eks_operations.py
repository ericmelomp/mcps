"""Targeted SG dependency and bounded historical Container Insights queries."""
import ipaddress
import math
import re
import time
from datetime import datetime, timedelta, timezone

from .aws import authenticated_session, error_code
from .config import resolve, ConfigurationError
from .contracts import envelope, bounded
from .eks_cli import CollectionError
from .eks_insights import quantity

SG = re.compile(r'^sg-(?:[a-f0-9]{8}|[a-f0-9]{17})$')
NAME = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,252}$')


def tcp_matches(rule, port):
    return rule.get('IpProtocol') == '-1' or (rule.get('IpProtocol') in {'tcp','6'} and rule.get('FromPort',-1)<=port<=rule.get('ToPort',-1))


def sg_ingress(groups, source, port, source_ip=None):
    matches=[]; unknown=False
    for group in groups:
        for rule in group.get('IpPermissions',[]):
            if not tcp_matches(rule,port): continue
            if any(p.get('GroupId')==source for p in rule.get('UserIdGroupPairs',[])):
                matches.append({'destination_sg':group['GroupId'],'type':'sg_reference','source_sg':source})
            for r in rule.get('IpRanges',[]):
                cidr=r.get('CidrIp')
                if cidr=='0.0.0.0/0' or source_ip and ipaddress.ip_address(source_ip) in ipaddress.ip_network(cidr):
                    matches.append({'destination_sg':group['GroupId'],'type':'cidr','cidr':cidr})
                elif source_ip is None: unknown=True
            if rule.get('PrefixListIds'): unknown=True
    return matches, unknown


def percentiles(values):
    data=sorted(float(x) for x in values)
    if not data or any(not math.isfinite(x) or x<0 for x in data):
        raise CollectionError('invalid_or_missing_metric_values')
    return {'samples':len(data),'average':sum(data)/len(data),'p95_bucket_maximum':data[max(0,math.ceil(.95*len(data))-1)],'maximum':data[-1]}


class EKSOperations:
    def __init__(self, store, factory=authenticated_session, clock=time.monotonic):
        self.store,self.factory,self.clock=store,factory,clock

    def query(self,account,region,kind,**target):
        result=envelope(account,region);result['items']=[]
        result['coverage'].update(scope='Targeted configuration/history evidence; no active probes or remediation')
        try:
            config=resolve(account,region)
            self.validate(kind,target)
            session,options=self.factory(config,region)
            deadline=self.clock()+45
            def call(service,method,**params):
                if self.clock()>=deadline: raise CollectionError('deadline_exceeded')
                return getattr(session.client(service,config=options),method)(**params)
            getattr(self,kind)(result,call,**target)
        except ConfigurationError:
            result['errors'].append({'code':'configuration_invalid'})
        except Exception as exc:
            result['errors'].append({'code':exc.code if isinstance(exc,CollectionError) else error_code(exc)})
        if result['errors']:
            result['coverage']['complete']=False
            result['status']='partial' if result['items'] else 'error'
        elif not result['coverage']['complete']: result['status']='partial'
        elif any(x.get('assessment') in {'missing_ingress_rule','review_rightsizing'} for x in result['items']): result['status']='degraded'
        result['summary']['returned_items']=len(result['items'])
        if result['items']:
            evidence=self.store.put(account,region,result['items'],result['coverage'])
            if evidence: result['evidence_id']=evidence
            else:
                result['coverage']['complete']=False
                result['errors'].append({'code':'evidence_unavailable'})
                result['status']='partial'
        return bounded(result)

    @staticmethod
    def validate(kind,target):
        if kind=='network':
            ids=target.get('source_security_group_ids',[])
            if not 1<=len(ids)<=5 or len(set(ids))!=len(ids) or any(not SG.fullmatch(x) for x in ids):
                raise CollectionError('invalid_source_security_groups')
            if target.get('destination_kind') not in {'redis','opensearch'} or not NAME.fullmatch(target.get('destination_name','')):
                raise CollectionError('invalid_destination')
            if target.get('source_private_ip'):
                ip=ipaddress.ip_address(target['source_private_ip'])
                if ip.version!=4 or not ip.is_private: raise CollectionError('private_ipv4_required')
        elif kind=='rightsizing':
            if any(not NAME.fullmatch(target.get(k,'')) for k in ('cluster','namespace','pod_name')):
                raise CollectionError('invalid_metric_target')
            hours=target.get('hours',168)
            if type(hours) is not int or not 24<=hours<=336: raise CollectionError('historical_window_24_to_336_hours')
            for k in ('cpu_request','memory_request'):
                if target.get(k):
                    try: quantity(target[k])
                    except ValueError: raise CollectionError("invalid_resource_quantity") from None
        else: raise CollectionError('operation_not_supported')

    def network(self,result,call,source_security_group_ids,destination_kind,destination_name,source_private_ip=''):
        port=6379 if destination_kind=='redis' else 443
        if destination_kind=='redis':
            raw=call('elasticache','describe_cache_clusters',CacheClusterId=destination_name,ShowCacheNodeInfo=True)['CacheClusters']
            if len(raw)!=1: raise CollectionError('destination_not_unique')
            obj=raw[0]
            dest_ids=[g['SecurityGroupId'] for g in obj.get('SecurityGroups',[])]
            endpoints=[n.get('Endpoint',{}) for n in obj.get('CacheNodes',[])]
            ports={e['Port'] for e in endpoints if 'Port' in e}
            if len(ports)!=1: raise CollectionError('redis_endpoint_port_unavailable')
            port=next(iter(ports))
            subnetgroup=call('elasticache','describe_cache_subnet_groups',CacheSubnetGroupName=obj['CacheSubnetGroupName'])['CacheSubnetGroups']
            dest_vpc=subnetgroup[0]['VpcId']
        else:
            obj=call('opensearch','describe_domain',DomainName=destination_name)['DomainStatus']
            dest_ids=obj.get('VPCOptions',{}).get('SecurityGroupIds',[])
            dest_vpc=obj.get('VPCOptions',{}).get('VPCId')
            endpoints=[{'Address':v,'Port':443} for v in obj.get('Endpoints',{}).values()]
        if not dest_ids: raise CollectionError('destination_vpc_security_groups_unavailable')
        rawgroups=call('ec2','describe_security_groups',GroupIds=list(dict.fromkeys(source_security_group_ids+dest_ids)))['SecurityGroups']
        groups={g['GroupId']:g for g in rawgroups}
        if any(g not in groups for g in source_security_group_ids+dest_ids): raise CollectionError('security_group_missing')
        verified=None
        if source_private_ip:
            r=call('ec2','describe_network_interfaces',Filters=[{'Name':'addresses.private-ip-address','Values':[source_private_ip]}],MaxResults=100)
            interfaces=r.get('NetworkInterfaces',[])
            if r.get('NextToken'): raise CollectionError('source_interface_lookup_partial')
            attached={g['GroupId'] for eni in interfaces for g in eni.get('Groups',[])}
            verified={g:g in attached for g in source_security_group_ids}
        result['summary'].update(destination=destination_name,port=port,destination_security_groups=dest_ids,endpoints=endpoints[:5],
                                 source_attribution='ENI lookup' if verified is not None else 'caller-supplied SGs; pod/node attachment unverified')
        for source in source_security_group_ids:
            inbound,unknown=sg_ingress([groups[g] for g in dest_ids],source,port,source_private_ip or None)
            egress=groups[source].get('IpPermissionsEgress',[])
            outbound=any(tcp_matches(r,port) and (any(x.get('CidrIp')=='0.0.0.0/0' for x in r.get('IpRanges',[])) or any(p.get('GroupId') in dest_ids for p in r.get('UserIdGroupPairs',[]))) for r in egress)
            other_egress=any(tcp_matches(r,port) and (r.get('IpRanges') or r.get('PrefixListIds')) for r in egress)
            assessment='sg_rule_observed' if inbound else ('ingress_unknown_without_source_ip_or_prefix_expansion' if unknown else 'missing_ingress_rule')
            result['items'].append({'kind':'network_dependency','source_sg':source,'destination_security_groups':dest_ids,
                'port':port,'protocol':'tcp','same_vpc':groups[source].get('VpcId')==dest_vpc,'assessment':assessment,
                'source_sg_attached_to_ip':verified[source] if verified is not None else None,
                'ingress_matches':inbound,'egress_assessment':'rule_observed' if outbound else ('unknown_destination_ip' if other_egress else 'no_rule_observed'),
                'proposed_rule':{'protocol':'tcp','from_port':port,'to_port':port,'source_sg':source,'destination_security_groups':dest_ids} if not inbound else None,
                'exclusions':['routes/peering/TGW/NACL','NetworkPolicy','TLS/authentication/domain policy','active connection test']})
        result['coverage']['connection_verified']=False

    def rightsizing(self,result,call,cluster,namespace,pod_name,hours=168,cpu_request='',memory_request=''):
        # Hour buckets of Maximum preserve observed peaks; this is not raw sample p95.
        end=datetime.now(timezone.utc).replace(minute=0,second=0,microsecond=0)
        start=end-timedelta(hours=hours)
        queries=[]
        for identifier,metric in (('cpu','pod_cpu_usage_total'),('memory','pod_memory_working_set')):
            queries.append({'Id':identifier,'MetricStat':{'Metric':{'Namespace':'ContainerInsights','MetricName':metric,
                            'Dimensions':[{'Name':'ClusterName','Value':cluster},{'Name':'Namespace','Value':namespace},{'Name':'PodName','Value':pod_name}]},
                            'Period':3600,'Stat':'Maximum'},'ReturnData':True})
        values={'cpu':{},'memory':{}}; statuses={'cpu':[],'memory':[]};tokens=set();params={}
        for _ in range(10):
            raw=call('cloudwatch','get_metric_data',StartTime=start,EndTime=end,MetricDataQueries=queries,MaxDatapoints=10000,ScanBy='TimestampAscending',**params)
            for series in raw.get('MetricDataResults',[]):
                key=series.get('Id')
                if key not in values: continue
                if len(series.get('Timestamps',[]))!=len(series.get('Values',[])): raise CollectionError('metric_timestamp_value_mismatch')
                statuses[key].append(series.get('StatusCode'))
                for stamp,value in zip(series.get('Timestamps',[]),series.get('Values',[])):
                    if not start<=stamp<end: continue
                    if stamp.minute or stamp.second or stamp.microsecond: raise CollectionError("metric_timestamp_not_hour_aligned")
                    if stamp in values[key] and values[key][stamp]!=value: raise CollectionError("metric_snapshot_inconsistent")
                    values[key][stamp]=value
                if len(values[key])>336: raise CollectionError('metric_datapoint_limit')
            token=raw.get('NextToken')
            if not token: break
            if token in tokens: raise CollectionError('metric_pagination_cycle')
            tokens.add(token);params={'NextToken':token}
        else: raise CollectionError('metric_page_limit')
        result['summary'].update(cluster=cluster,namespace=namespace,pod_name=pod_name,start=start.isoformat(),end=end.isoformat(),hours=hours,
                                 statistic='Maximum per hour; percentiles across hour maxima',dimension_scope='PodName may aggregate replicas; not container/per-replica sizing')
        for resource in ('cpu','memory'):
            data=values[resource]
            complete=bool(data) and statuses[resource] and all(s=='Complete' for s in statuses[resource])
            coverage=len(data)/hours
            if not complete: result['errors'].append({'code':'metric_missing_or_partial','resource':resource})
            stats=percentiles(data.values()) if data else None
            req=quantity(cpu_request)*1000 if resource=='cpu' and cpu_request else quantity(memory_request) if resource=='memory' and memory_request else None
            candidate=None
            if complete and coverage>=.8 and stats and req is not None:
                # CPU/memory reductions need configuration continuity and functional review.
                candidate=stats['maximum']*1.3
            result['items'].append({'kind':'rightsizing_history','resource':resource,'units':'millicores' if resource=='cpu' else 'bytes',
                'stats':stats,'expected_hour_buckets':hours,'observed_coverage_ratio':round(coverage,3),'api_complete':bool(complete),
                'request_reference':req,'candidate_request_with_30_percent_margin':candidate,
                'assessment':'review_rightsizing' if candidate is not None else 'insufficient_evidence',
                'request_reference_source':'caller_supplied_current_value','gaps':['configuration changes during window not tracked','PodName aggregation must be verified','startup peaks absent from sparse history'],
                'apply_recommendation':False})
        if any(len(v)<hours*.8 for v in values.values()):
            result['coverage']['complete']=False
            result['status']='partial'
