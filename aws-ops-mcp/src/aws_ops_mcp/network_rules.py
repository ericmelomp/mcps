"""Pure IPv4 route, stateful SG and stateless NACL evaluation."""
import ipaddress

ROUTE_TARGETS = ('GatewayId','NatGatewayId','TransitGatewayId','VpcPeeringConnectionId','NetworkInterfaceId','InstanceId','EgressOnlyInternetGatewayId','LocalGatewayId','CarrierGatewayId','CoreNetworkArn')


def ipv4(value):
    try:
        address=ipaddress.ip_address(value)
        if address.version!=4: raise ValueError()
        return address
    except ValueError: raise ValueError('ipv4_required') from None


def protocol_matches(value,protocol):
    return str(value) in {'-1',protocol,{'tcp':'6','udp':'17'}[protocol]}


def permission_matches(rule,protocol,port):
    return protocol_matches(rule.get('IpProtocol'),protocol) and (str(rule.get('IpProtocol'))=='-1' or rule.get('FromPort',-1)<=port<=rule.get('ToPort',-1))


def longest_route(routes,address,prefix_entries=None):
    ip=ipv4(address); matches=[]; unknown=False
    for route in routes:
        cidrs=[route['DestinationCidrBlock']] if route.get('DestinationCidrBlock') else []
        if route.get('DestinationPrefixListId'):
            entries=(prefix_entries or {}).get(route['DestinationPrefixListId'])
            if entries is None: unknown=True
            else: cidrs+=entries
        for cidr in cidrs:
            network=ipaddress.ip_network(cidr)
            if network.version==4 and ip in network: matches.append((network.prefixlen,route))
    if unknown: return {'assessment':'unknown_prefix_list_route','route':None}
    if not matches: return {'assessment':'no_route','route':None}
    length=max(x[0] for x in matches);best=[r for l,r in matches if l==length]
    targets={tuple((k,r.get(k)) for k in ROUTE_TARGETS if r.get(k)) for r in best}
    if len(targets)>1: return {'assessment':'ambiguous_equal_prefix_routes','route':None}
    route=best[0]
    return {'assessment':'blackhole' if route.get('State')=='blackhole' else ('route_observed' if route.get('State')=='active' else 'route_state_unknown'),
            'route':{k:route[k] for k in ('DestinationCidrBlock','DestinationPrefixListId','State','Origin',*ROUTE_TARGETS) if k in route}}


def sg_decision(groups,direction,peer_ip,peer_sgs,protocol,port,reference_supported=True,prefix_entries=None):
    ip=ipv4(peer_ip);matches=[];unknown=False
    key='IpPermissions' if direction=='ingress' else 'IpPermissionsEgress'
    for group in groups:
        for rule in group.get(key,[]):
            if not permission_matches(rule,protocol,port): continue
            cidrs=[r['CidrIp'] for r in rule.get('IpRanges',[]) if r.get('CidrIp')]
            for ref in rule.get('PrefixListIds',[]):
                entries=(prefix_entries or {}).get(ref.get('PrefixListId'))
                if entries is None: unknown=True
                else: cidrs+=entries
            if any(ip in ipaddress.ip_network(c) for c in cidrs if ipaddress.ip_network(c).version==4):
                matches.append({'group_id':group['GroupId'],'via':'cidr_or_prefix_list'})
            for ref in rule.get('UserIdGroupPairs',[]):
                if ref.get('GroupId') in peer_sgs:
                    if reference_supported: matches.append({'group_id':group['GroupId'],'via':'sg_reference','peer_sg':ref['GroupId']})
                    else: unknown=True
    return {'assessment':'allow_rule_observed' if matches else ('unknown_reference_support' if unknown else 'no_allow_rule'), 'matches':matches[:20],'matches_truncated':len(matches)>20}


def nacl_one(entries,egress,peer_ip,protocol,port):
    ip=ipv4(peer_ip)
    for rule in sorted(entries,key=lambda r:r['RuleNumber']):
        if bool(rule.get('Egress')) != egress: continue
        cidr=rule.get('CidrBlock')
        if not cidr or ip not in ipaddress.ip_network(cidr): continue
        if not protocol_matches(rule.get('Protocol'),protocol): continue
        ports=rule.get('PortRange',{})
        if str(rule.get('Protocol'))!='-1' and not ports.get('From',0)<=port<=ports.get('To',65535): continue
        return {'action':rule.get('RuleAction','unknown'),'rule_number':rule['RuleNumber'],'cidr':cidr}
    return {'action':'deny','rule_number':32767,'implicit':True}


def nacl_range(entries,egress,peer_ip,protocol,low,high):
    points={low,high+1}
    for rule in entries:
        ports=rule.get('PortRange',{})
        for point in (ports.get('From'), ports.get('To',-1)+1):
            if point is not None and low<point<=high: points.add(point)
    points=sorted(points)
    spans=[]
    for left,right in zip(points,points[1:]):
        decision=nacl_one(entries,egress,peer_ip,protocol,left)
        spans.append({'from_port':left,'to_port':right-1,**decision})
    actions={x['action'] for x in spans}
    assessment='allow' if actions=={'allow'} else ('deny' if actions=={'deny'} else 'mixed_or_unknown')
    return {'assessment':assessment,'ranges':spans[:10],'ranges_truncated':len(spans)>10}
