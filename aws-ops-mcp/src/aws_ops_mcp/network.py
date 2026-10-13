"""Read-only ENI paths and standard VPC Flow Logs with explicit coverage gaps."""
import ipaddress
import re
import time
from datetime import timedelta
from .aws import authenticated_session,error_code
from .config import resolve,ConfigurationError
from .contracts import envelope,bounded
from .eks_cli import CollectionError
from .security import utc
from .network_rules import ipv4,longest_route,sg_decision,nacl_one,nacl_range

ENI=re.compile(r'^eni-(?:[a-f0-9]{8}|[a-f0-9]{17})$')


class Context:
    def __init__(self,factory,region,clock):
        self.factory,self.region,self.clock=factory,region,clock
        self.deadline=clock()+45;self.sessions={};self.prefixes={}
    def connect(self,alias):
        if alias not in self.sessions:
            if self.clock()>=self.deadline: raise CollectionError('deadline_exceeded')
            config=resolve(alias,self.region)
            session,options=self.factory(config,self.region)
            self.sessions[alias]=(session,options,config.account_id)
        return self.sessions[alias]
    def call(self,alias,service,method,**params):
        if self.clock()>=self.deadline: raise CollectionError('deadline_exceeded')
        session,options,_=self.connect(alias)
        return getattr(session.client(service,config=options),method)(**params)
    def pages(self,alias,service,method,key,**params):
        seen=set();count=0
        for _ in range(10):
            raw=self.call(alias,service,method,**params)
            rows=raw.get(key,[]);count+=len(rows)
            if count>1000: raise CollectionError('network_object_limit')
            yield from rows
            token=raw.get('NextToken') or raw.get('nextToken')
            if not token: return
            if token in seen: raise CollectionError('network_pagination_cycle')
            seen.add(token);params['nextToken' if service=='logs' else 'NextToken']=token
        raise CollectionError('network_page_limit')
    def prefix_map(self,alias,ids):
        values={}
        for identifier in sorted(ids):
            key=(alias,identifier)
            if key not in self.prefixes:
                rows=list(self.pages(alias,'ec2','get_managed_prefix_list_entries','Entries',PrefixListId=identifier,MaxResults=100))
                self.prefixes[key]=[r['Cidr'] for r in rows]
            values[identifier]=self.prefixes[key]
        return values


class Network:
    def __init__(self,store,factory=authenticated_session,clock=time.monotonic):
        self.store,self.factory,self.clock=store,factory,clock
    def query(self,account,region,kind,**target):
        result=envelope(account,region);result['items']=[]
        result['summary']['connection_verified']=False
        result['coverage'].update(scope='One IPv4 path or retained standard CloudWatch VPC Flow Logs; no active probes')
        try:
            self.validate(kind,target)
            context=Context(self.factory,region,self.clock);context.connect(account)
            getattr(self,kind)(result,context,account,**target)
        except ConfigurationError: result['errors'].append({'code':'configuration_invalid'})
        except Exception as exc: result['errors'].append({'code':exc.code if isinstance(exc,CollectionError) else error_code(exc)})
        if result['errors']:
            result['coverage']['complete']=False
            result['status']='partial' if result['items'] else 'error'
            result['summary']['assessment']='insufficient_evidence'
        elif not result['coverage']['complete']:result['status']='partial'
        elif result['summary'].get('assessment')=='configuration_blocked':result['status']='degraded'
        if result['items']:
            identifier=self.store.put(account,region,result['items'],result['coverage'])
            if identifier: result['evidence_id']=identifier
            else:
                result['errors'].append({'code':'evidence_unavailable'});result['coverage']['complete']=False;result['status']='partial'
        return bounded(result)
    @staticmethod
    def validate(kind,t):
        if kind=='path':
            if any(not ENI.fullmatch(t.get(k,'')) for k in ('source_eni_id','destination_eni_id')):raise CollectionError('invalid_eni_id')
            if t.get('protocol','tcp') not in {'tcp','udp'}:raise CollectionError('unsupported_protocol')
            if type(t.get('port')) is not int or not 1<=t['port']<=65535:raise CollectionError('invalid_destination_port')
            if type(t.get('source_port',0)) is not int or not 0<=t.get('source_port',0)<=65535:raise CollectionError('invalid_source_port')
            for k in ('source_ip','destination_ip'):
                if t.get(k):
                    try:ipv4(t[k])
                    except ValueError:raise CollectionError('ipv4_required') from None
        elif kind=='flows':
            if not t.get('log_group_name') or len(t['log_group_name'])>512:raise CollectionError('invalid_log_group')
            start,end=utc(t['start_time']),utc(t['end_time'])
            if not timedelta(0)<end-start<=timedelta(hours=1):raise CollectionError('flow_window_positive_max_1h')
            if not any(t.get(k) for k in ('interface_id','source_ip','destination_ip')):raise CollectionError('flow_selector_required')
            if t.get('interface_id') and not ENI.fullmatch(t['interface_id']):raise CollectionError('invalid_eni_id')
            if type(t.get('port',0)) is not int or not 0<=t.get('port',0)<=65535:raise CollectionError('invalid_port')
            for k in ('source_ip','destination_ip'):
                if t.get(k):
                    try:ipv4(t[k])
                    except ValueError:raise CollectionError('ipv4_required') from None
        else:raise CollectionError('unsupported_network_operation')
    @staticmethod
    def address(eni,value):
        addresses={p['PrivateIpAddress'] for p in eni.get('PrivateIpAddresses',[])}|{eni.get('PrivateIpAddress')}
        value=value or eni.get('PrivateIpAddress')
        if not value:raise CollectionError('eni_private_ipv4_unavailable')
        ip=ipv4(value)
        if value not in addresses and not any(ip in ipaddress.ip_network(p['Ipv4Prefix']) for p in eni.get('Ipv4Prefixes',[])):
            raise CollectionError('ip_not_attached_to_eni')
        return str(ip)
    def route_table(self,c,alias,eni):
        tables=list(c.pages(alias,'ec2','describe_route_tables','RouteTables',Filters=[{'Name':'association.subnet-id','Values':[eni['SubnetId']]}]))
        if not tables:tables=list(c.pages(alias,'ec2','describe_route_tables','RouteTables',Filters=[{'Name':'vpc-id','Values':[eni['VpcId']]},{'Name':'association.main','Values':['true']}]))
        if len(tables)!=1:raise CollectionError('route_table_not_unique')
        return tables[0]
    def path(self,result,c,account,source_eni_id,destination_eni_id,port,protocol='tcp',source_port=0,source_ip='',destination_ip='',destination_account='',network_account=''):
        destination_account=destination_account or account;owner=network_account or account
        def eni(alias,identifier):
            rows=c.call(alias,'ec2','describe_network_interfaces',NetworkInterfaceIds=[identifier])['NetworkInterfaces']
            if len(rows)!=1 or rows[0].get('Status')!='in-use':raise CollectionError('eni_not_unique_or_not_in_use')
            return rows[0]
        src,dst=eni(account,source_eni_id),eni(destination_account,destination_eni_id)
        sip,dip=self.address(src,source_ip),self.address(dst,destination_ip)
        result['summary'].update(source_ip=sip,destination_ip=dip,protocol=protocol,destination_port=port,source_port=source_port or 'unknown_ephemeral_range_1024_65535')
        for role,e in (('source',src),('destination',dst)):
            result['items'].append({'kind':'network_endpoint','role':role,'eni_id':e['NetworkInterfaceId'],'vpc_id':e['VpcId'],'subnet_id':e['SubnetId'],'security_groups':[g['GroupId'] for g in e.get('Groups',[])]})
        decisions=[];tables={};views={}
        for role,e,peerip in (('source',src,dip),('destination',dst,sip)):
            table=self.route_table(c,owner,e);tables[role]=table
            prefixes=c.prefix_map(owner,{r['DestinationPrefixListId'] for r in table.get('Routes',[]) if r.get('DestinationPrefixListId')})
            view=longest_route(table.get('Routes',[]),peerip,prefixes);views[role]=view
            result['items'].append({'kind':'network_route','role':role,'table_id':table['RouteTableId'],**view})
            decisions.append(view['assessment'])
        forward=views['source'].get('route') or {};back=views['destination'].get('route') or {}
        same=src['VpcId']==dst['VpcId'];direct=False
        if same and forward.get('GatewayId')==back.get('GatewayId')=='local':direct=True
        peer=forward.get('VpcPeeringConnectionId')
        if peer and peer==back.get('VpcPeeringConnectionId'):
            peers=c.call(owner,'ec2','describe_vpc_peering_connections',VpcPeeringConnectionIds=[peer]).get('VpcPeeringConnections',[])
            p=peers[0] if len(peers)==1 else {}
            pair={p.get('RequesterVpcInfo',{}).get('VpcId'),p.get('AccepterVpcInfo',{}).get('VpcId')}
            direct=p.get('Status',{}).get('Code')=='active' and pair=={src['VpcId'],dst['VpcId']}
            result['items'].append({'kind':'network_peering','id':peer,'state':p.get('Status',{}).get('Code'),'expected_vpcs':pair=={src['VpcId'],dst['VpcId']}})
            if not direct:decisions.append('peering_not_active_or_wrong_vpcs')
        tgw=forward.get('TransitGatewayId')
        if tgw and tgw==back.get('TransitGatewayId'):
            self.transit(result,c,owner,tgw,src,dst,sip,dip,decisions)
            decisions.append('tgw_attachment_subnet_nacls_not_assessed')
        elif not direct and all(x=='route_observed' for x in decisions):decisions.append('intermediate_path_not_traced')
        sg_refs=direct
        for role,e,alias,direction,peerip,peer_eni in (('source',src,account,'egress',dip,dst),('destination',dst,destination_account,'ingress',sip,src)):
            ids=[g['GroupId'] for g in e.get('Groups',[])]
            groups=c.call(alias,'ec2','describe_security_groups',GroupIds=ids).get('SecurityGroups',[]) if ids else []
            if len(groups)!=len(ids):raise CollectionError('security_group_lookup_incomplete')
            prefixes=c.prefix_map(alias,{p['PrefixListId'] for g in groups for r in g.get('IpPermissions' if direction=='ingress' else 'IpPermissionsEgress',[]) for p in r.get('PrefixListIds',[])})
            d=sg_decision(groups,direction,peerip,{g['GroupId'] for g in peer_eni.get('Groups',[])},protocol,port,sg_refs,prefixes)
            result['items'].append({'kind':'network_security_group','role':role,'direction':direction,**d});decisions.append(d['assessment'])
            acls=list(c.pages(owner,'ec2','describe_network_acls','NetworkAcls',Filters=[{'Name':'association.subnet-id','Values':[e['SubnetId']]}]))
            if len(acls)!=1:raise CollectionError('nacl_not_unique')
            acl=acls[0];egress=role=='source'
            d=nacl_one(acl.get('Entries',[]),egress,peerip,protocol,port)
            result['items'].append({'kind':'network_nacl','role':role,'direction':'egress' if egress else 'ingress','leg':'forward','nacl_id':acl['NetworkAclId'],**d});decisions.append(d['action'])
            r=nacl_range(acl.get('Entries',[]),not egress,peerip,protocol,source_port or 1024,source_port or 65535)
            result['items'].append({'kind':'network_nacl','role':role,'direction':'ingress' if egress else 'egress','leg':'return','nacl_id':acl['NetworkAclId'],**r});decisions.append(r['assessment'] if source_port or r['assessment']=='allow' else 'return_port_unknown_with_range_denial')
        blocked=any(x in {'no_route','blackhole','no_allow_rule','deny','peering_not_active_or_wrong_vpcs','tgw_blackhole_or_wrong_attachment'} for x in decisions)
        unknown=any(x not in {'route_observed','allow_rule_observed','allow','no_route','blackhole','no_allow_rule','deny','peering_not_active_or_wrong_vpcs','tgw_blackhole_or_wrong_attachment'} for x in decisions)
        result['summary']['assessment']='configuration_blocked' if blocked and 'intermediate_path_not_traced' not in decisions else ('insufficient_evidence' if unknown else 'configuration_consistent')
        result['coverage']['complete']=not unknown
        result['summary']['checks_with_gaps']=[d for d in decisions if d not in {'route_observed','allow_rule_observed','allow','no_route','blackhole','no_allow_rule','deny','peering_not_active_or_wrong_vpcs','tgw_blackhole_or_wrong_attachment'}]
        result['coverage']['exclusions']=['DNS','application listener/TLS/authentication','NetworkPolicy/host firewall','appliances/NAT translation','TGW attachment-subnet NACLs','SG referencing via TGW feature settings','active probes']
    def transit(self,result,c,owner,identifier,src,dst,sip,dip,decisions):
        attachments=list(c.pages(owner,'ec2','describe_transit_gateway_attachments','TransitGatewayAttachments',Filters=[{'Name':'transit-gateway-id','Values':[identifier]},{'Name':'resource-id','Values':[src['VpcId'],dst['VpcId']]}]))
        pairs={v:[a for a in attachments if a.get('ResourceId')==v and a.get('ResourceType')=='vpc' and a.get('State')=='available'] for v in (src['VpcId'],dst['VpcId'])}
        if any(len(v)!=1 for v in pairs.values()):decisions.append('tgw_attachments_unknown');return
        for role,e,peer,peerip in (('source',src,dst,dip),('destination',dst,src,sip)):
            att=pairs[e['VpcId']][0];dest=pairs[peer['VpcId']][0];assoc=att.get('Association',{})
            if assoc.get('State')!='associated' or not assoc.get('TransitGatewayRouteTableId'):decisions.append('tgw_association_unknown');continue
            raw=c.call(owner,'ec2','search_transit_gateway_routes',TransitGatewayRouteTableId=assoc['TransitGatewayRouteTableId'],Filters=[{'Name':'route-search.longest-prefix-match','Values':[peerip+'/32']}],MaxResults=50)
            routes=raw.get('Routes',[])
            if raw.get('AdditionalRoutesAvailable'):decisions.append('tgw_route_lookup_partial')
            valid=[r for r in routes if r.get('State')=='active' and any(a.get('TransitGatewayAttachmentId')==dest['TransitGatewayAttachmentId'] for a in r.get('TransitGatewayAttachments',[]))]
            state='route_observed' if len(valid)==1 and len(routes)==1 and not raw.get('AdditionalRoutesAvailable') else ('tgw_blackhole_or_wrong_attachment' if routes and all(r.get('State')=='blackhole' for r in routes) else 'tgw_next_hop_unknown')
            decisions.append(state)
            result['items'].append({'kind':'network_tgw_route','role':role,'tgw_id':identifier,'table_id':assoc['TransitGatewayRouteTableId'],'source_attachment':att['TransitGatewayAttachmentId'],'expected_destination_attachment':dest['TransitGatewayAttachmentId'],'assessment':state})
    def flows(self,result,c,account,log_group_name,start_time,end_time,interface_id='',source_ip='',destination_ip='',port=0):
        start,end=utc(start_time),utc(end_time)
        selector=interface_id or source_ip or destination_ip
        params={'logGroupName':log_group_name,'startTime':int(start.timestamp()*1000),'endTime':int(end.timestamp()*1000),
                'filterPattern':'"'+selector+'"','limit':1000}
        expected=c.connect(account)[2]
        count=matched=malformed=skipped=nodata=foreign=0;actions={'ACCEPT':0,'REJECT':0};seen=set()
        result['coverage'].update(start=start.isoformat(),end_exclusive=end.isoformat(),history_complete=False)
        for event in c.pages(account,'logs','filter_log_events','events',**params):
            count+=1
            if count>1000:raise CollectionError('flow_scan_limit')
            eid=event.get('eventId')
            if eid and eid in seen:continue
            if eid:seen.add(eid)
            record=parse_flow(event.get('message',''))
            if record is None:malformed+=1;continue
            if record['account_id']!=expected:
                foreign+=1;continue
            if interface_id and record['interface_id']!=interface_id:continue
            if record['log_status']=='SKIPDATA':skipped+=1;continue
            if record['log_status']=='NODATA':nodata+=1;continue
            if source_ip and record['source_ip']!=source_ip:continue
            if destination_ip and record['destination_ip']!=destination_ip:continue
            if port and record['destination_port']!=port:continue
            if record['end']<start.timestamp() or record['start']>=end.timestamp():continue
            matched+=1;actions[record['action']]+=1
            result['items'].append({'kind':'vpc_flow',**record})
            if matched>=200:raise CollectionError('flow_match_limit')
        result['summary'].update(scanned=count,matched=matched,actions=actions,skipdata=skipped,nodata=nodata,
                                 malformed_or_custom_format=malformed,other_account_records_omitted=foreign,
                                 assessment='flow_reject_observed' if actions['REJECT'] else ('flow_accept_observed' if actions['ACCEPT'] else 'no_matching_retained_record'),
                                 interpretation='ACCEPT does not prove listener/TLS/application success; REJECT alone does not identify SG vs NACL')
        result['coverage']['complete']=not skipped and not malformed and not foreign
        result['coverage']['exclusions']=['S3 Flow Logs','custom reordered log formats','delivery latency and retention gaps','packet payload','active probes']


def parse_flow(message):
    """Default v2 field order only; never return arbitrary message text."""
    fields=message.split()
    if len(fields)<14:return None
    version,account,interface,src,dst,sport,dport,proto,packets,bytes_,start,end,action,status=fields[:14]
    try:
        if not version.isdigit() or not 2<=int(version)<=5 or not re.fullmatch(r'\d{12}',account) or not ENI.fullmatch(interface):return None
        if status not in {'OK','NODATA','SKIPDATA'}:return None
        base={'account_id':account,'interface_id':interface,'log_status':status}
        if status!='OK':return base
        src,dst=str(ipv4(src)),str(ipv4(dst))
        values=[int(x) for x in (sport,dport,proto,packets,bytes_,start,end)]
        if any(x<0 for x in values) or values[0]>65535 or values[1]>65535 or values[2]>255 or values[5]>values[6] or action not in {'ACCEPT','REJECT'}:return None
        return {**base,'source_ip':src,'destination_ip':dst,'source_port':values[0],'destination_port':values[1],
                'protocol':values[2],'packets':values[3],'bytes':values[4],'start':values[5],'end':values[6],'action':action}
    except (ValueError,TypeError):return None
