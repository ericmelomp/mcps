"""Regional VPC topology, deterministic configuration signals and explicit component gaps."""
import ipaddress
import re
from collections import Counter
from .eks_cli import CollectionError
from .ops_runtime import safe_error


def validate(vpc_ids):
    if not isinstance(vpc_ids,list) or len(vpc_ids)>5 or len(set(vpc_ids))!=len(vpc_ids) or any(
        not isinstance(v,str) or not re.fullmatch(r'vpc-(?:[a-f0-9]{8}|[a-f0-9]{17})',v) for v in vpc_ids):
        raise CollectionError('invalid_vpc_selection')


def collect(context,result,vpc_ids=None,include_hybrid=False):
    vpc_ids=vpc_ids or []
    validate(vpc_ids)
    def rows(method,key,**params):
        try:
            yield from context.pages('ec2',method,key,**params)
        except Exception as exc:
            result['errors'].append({'code':safe_error(exc),'component':method})
            if len(result['errors'])>=20:raise CollectionError('component_error_limit')
    def add(row):
        if len(result['items'])>=5000:raise CollectionError('evidence_item_limit')
        result['items'].append(row)
    def finding(code,resource,severity='warning',confidence='confirmed',**evidence):
        if len(result['findings'])>=1000:raise CollectionError('finding_limit')
        result['findings'].append({'code':code,'resource_id':resource,'severity':severity,'confidence':confidence,
                                   'evidence':evidence,'recommendations':['Review configuration and validate the intended traffic path']})
    networks={}
    params={'VpcIds':vpc_ids} if vpc_ids else {}
    for vpc in rows('describe_vpcs','Vpcs',**params):
        if len(networks)>=50:raise CollectionError('vpc_limit')
        identifier=vpc['VpcId'];cidrs=[]
        for association in vpc.get('CidrBlockAssociationSet',[]):
            if association.get('CidrBlockState',{}).get('State')=='associated':cidrs.append(association['CidrBlock'])
        if not cidrs and vpc.get('CidrBlock'):cidrs.append(vpc['CidrBlock'])
        cidrs.extend(a['Ipv6CidrBlock'] for a in vpc.get('Ipv6CidrBlockAssociationSet',[]) if a.get('Ipv6CidrBlockState',{}).get('State')=='associated')
        networks[identifier]=[ipaddress.ip_network(c) for c in cidrs]
        add({'kind':'vpc','resource_id':identifier,'owner_id':vpc.get('OwnerId'),'state':vpc.get('State'),
             'cidrs':cidrs,'is_default':vpc.get('IsDefault',False)})
        for attr in ('enableDnsSupport','enableDnsHostnames'):
            try:
                value=context.call('ec2','describe_vpc_attribute',VpcId=identifier,Attribute=attr)
                key=attr[0].upper()+attr[1:]
                add({'kind':'vpc_dns_attribute','resource_id':identifier,'attribute':attr,'value':value[key]['Value']})
                if not value[key]['Value']:finding('vpc_dns_attribute_disabled',identifier,'info',attribute=attr)
            except Exception as exc:
                result['errors'].append({'code':safe_error(exc),'component':attr})
                if len(result['errors'])>=20:raise CollectionError('component_error_limit')
    if not networks:
        if not result['errors']:result['errors'].append({'code':'no_vpcs_observed','component':'vpcs'})
        return
    if vpc_ids and set(vpc_ids)!=set(networks):result['errors'].append({'code':'vpc_selection_incomplete','component':'vpcs'})
    identifiers=sorted(networks)
    for i,left in enumerate(identifiers):
        for right in identifiers[i+1:]:
            matches=[(str(a),str(b)) for a in networks[left] for b in networks[right] if a.version==b.version and a.overlaps(b)]
            if matches: finding('vpc_cidr_overlap',left,peer_vpc=right,overlaps=matches[:10])
    filters=[{'Name':'vpc-id','Values':identifiers}]
    subnets={}
    for subnet in rows('describe_subnets','Subnets',Filters=filters):
        subnets[subnet['SubnetId']]=subnet
        add({'kind':'subnet','resource_id':subnet['SubnetId'],'vpc_id':subnet['VpcId'],
             'az':subnet.get('AvailabilityZone'),'ipv4_cidr':subnet.get('CidrBlock'),
             'ipv6_cidrs':[a['Ipv6CidrBlock'] for a in subnet.get('Ipv6CidrBlockAssociationSet',[]) if a.get('Ipv6CidrBlockState',{}).get('State')=='associated'],
             'map_public_ip_on_launch':subnet.get('MapPublicIpOnLaunch',False),
             'available_ipv4_addresses':subnet.get('AvailableIpAddressCount')})
    for table in rows('describe_route_tables','RouteTables',Filters=filters):
        add({'kind':'route_table','resource_id':table['RouteTableId'],'vpc_id':table['VpcId'],
             'associations':[{k:a[k] for k in ('SubnetId','GatewayId','Main') if k in a} for a in table.get('Associations',[])],
             'routes':[{k:r[k] for k in ('DestinationCidrBlock','DestinationIpv6CidrBlock','DestinationPrefixListId',
                 'GatewayId','NatGatewayId','TransitGatewayId','VpcPeeringConnectionId','NetworkInterfaceId',
                 'EgressOnlyInternetGatewayId','State','Origin') if k in r} for r in table.get('Routes',[])][:200]})
        if len(table.get('Routes',[]))>200:result['errors'].append({'code':'route_projection_limit','component':'routes'})
        for route in table.get('Routes',[]):
            if route.get('State')=='blackhole':finding('route_blackhole',table['RouteTableId'],'high',
                destination=route.get('DestinationCidrBlock',route.get('DestinationIpv6CidrBlock',route.get('DestinationPrefixListId'))))
            nat=route.get('NatGatewayId');subnet_ids=[a['SubnetId'] for a in table.get('Associations',[]) if a.get('SubnetId')]
            if nat:add({'kind':'route_dependency','resource_id':table['RouteTableId'],'target_id':nat,'subnet_ids':subnet_ids})
    for nat in rows('describe_nat_gateways','NatGateways',Filter=filters):
        add({'kind':'nat_gateway','resource_id':nat['NatGatewayId'],'vpc_id':nat['VpcId'],
             'subnet_id':nat.get('SubnetId'),'state':nat.get('State'),'connectivity_type':nat.get('ConnectivityType'),
             'public_ips':[a['PublicIp'] for a in nat.get('NatGatewayAddresses',[]) if a.get('PublicIp')]})
        if nat.get('State')=='failed':finding('nat_gateway_failed',nat['NatGatewayId'],'high')
    for gateway in rows('describe_internet_gateways','InternetGateways',Filters=[{'Name':'attachment.vpc-id','Values':identifiers}]):
        add({'kind':'internet_gateway','resource_id':gateway['InternetGatewayId'],
             'attachments':[{k:a[k] for k in ('VpcId','State') if k in a} for a in gateway.get('Attachments',[])]})
    for endpoint in rows('describe_vpc_endpoints','VpcEndpoints',Filters=filters):
        add({'kind':'vpc_endpoint','resource_id':endpoint['VpcEndpointId'],'vpc_id':endpoint['VpcId'],
             'type':endpoint.get('VpcEndpointType'),'service':endpoint.get('ServiceName'),'state':endpoint.get('State'),
             'private_dns_enabled':endpoint.get('PrivateDnsEnabled'),'subnet_ids':endpoint.get('SubnetIds',[]),
             'route_table_ids':endpoint.get('RouteTableIds',[]),'sg_ids':[g['GroupId'] for g in endpoint.get('Groups',[])]})
        if endpoint.get('State') in {'failed','rejected','expired'}:finding('vpc_endpoint_unavailable',endpoint['VpcEndpointId'],'high',state=endpoint['State'])
    for peer in rows('describe_vpc_peering_connections','VpcPeeringConnections'):
        src=peer.get('RequesterVpcInfo',{});dst=peer.get('AccepterVpcInfo',{})
        if src.get('VpcId') not in networks and dst.get('VpcId') not in networks:continue
        add({'kind':'vpc_peering','resource_id':peer['VpcPeeringConnectionId'],'state':peer.get('Status',{}).get('Code'),
             'requester':{k:src[k] for k in ('VpcId','OwnerId','Region','CidrBlock') if k in src},
             'accepter':{k:dst[k] for k in ('VpcId','OwnerId','Region','CidrBlock') if k in dst}})
    for attachment in rows('describe_transit_gateway_vpc_attachments','TransitGatewayVpcAttachments',Filters=filters):
        add({'kind':'tgw_vpc_attachment','resource_id':attachment['TransitGatewayAttachmentId'],
             'vpc_id':attachment['VpcId'],'tgw_id':attachment['TransitGatewayId'],'state':attachment.get('State'),
             'subnet_ids':attachment.get('SubnetIds',[])})
    for group in rows('describe_security_groups','SecurityGroups',Filters=filters):
        for rule in group.get('IpPermissions',[]):
            public=[r['CidrIp'] for r in rule.get('IpRanges',[]) if r.get('CidrIp')=='0.0.0.0/0']
            public += [r['CidrIpv6'] for r in rule.get('Ipv6Ranges',[]) if r.get('CidrIpv6')=='::/0']
            if public: finding('public_ingress_rule_observed',group['GroupId'],'warning','possible',
                               cidrs=public,protocol=rule.get('IpProtocol'),from_port=rule.get('FromPort'),to_port=rule.get('ToPort'))
    if include_hybrid:
        # VPN customer gateway configuration and tunnel options may contain PSKs; never project them.
        for vpn in rows('describe_vpn_connections','VpnConnections'):
            add({'kind':'vpn_connection','resource_id':vpn['VpnConnectionId'],'state':vpn.get('State'),
                 'tgw_id':vpn.get('TransitGatewayId'),'vgw_id':vpn.get('VpnGatewayId'),
                 'telemetry':[{k:(str(t[k]) if k=='LastStatusChange' else t[k]) for k in ('Status','AcceptedRouteCount','LastStatusChange') if k in t}
                              for t in vpn.get('VgwTelemetry',[])]})
            if any(t.get('Status')=='DOWN' for t in vpn.get('VgwTelemetry',[])):finding('vpn_tunnel_down',vpn['VpnConnectionId'],'warning')
        try:
            connections=context.call('directconnect','describe_connections').get('connections',[])
            if len(connections)>1000:raise CollectionError('direct_connect_limit')
            for connection in connections:
                add({'kind':'direct_connect','resource_id':connection['connectionId'],'state':connection.get('connectionState'),
                     'region':connection.get('region'),'bandwidth':connection.get('bandwidth')})
        except Exception as exc:result['errors'].append({'code':safe_error(exc),'component':'direct_connect'})
    counts=Counter(r['kind'] for r in result['items'])
    result['summary'].update(observed_resources=dict(counts),assessment='configuration_signals_only',
                             connectivity_verified=False,hybrid_scope='regional_all' if include_hybrid else 'excluded')
    result['coverage'].update(service_scope='Regional selected VPCs; shared/cross-account topology requires separate aliases',
        exclusions=['active probes','effective NACL/SG path evaluation (use network_path_inspect)',
                    'Cloud WAN/IPAM/Network Firewall','full TGW routes/propagation','customer on-prem routes/BGP',
                    'endpoint policy evaluation','DNS resolver runtime','cross-account completeness'])
