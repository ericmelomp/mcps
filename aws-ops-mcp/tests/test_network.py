from datetime import datetime,timezone
from unittest.mock import MagicMock
import json
import pytest
from botocore.exceptions import ClientError
from aws_ops_mcp.network import Network,Context,parse_flow
from aws_ops_mcp.network_rules import longest_route,sg_decision,nacl_one,nacl_range
from aws_ops_mcp.evidence import EvidenceStore
from aws_ops_mcp.eks_cli import CollectionError

SRC='eni-00000000000000001';DST='eni-00000000000000002'
SG1='sg-00000000000000001';SG2='sg-00000000000000002'
S1='subnet-00000001';S2='subnet-00000002';VPC='vpc-00000001'
PARAMS={'source_eni_id':SRC,'destination_eni_id':DST,'port':443}


class EC2:
    def __init__(self):
        self.calls=[];self.destination_vpc=VPC;self.ingress=True;self.blackhole=False;self.main=False;self.return_deny=False;self.nat=False;self.peer=False;self.peer_active=True;self.tgw=False;self.tgw_blackhole=False
    def describe_network_interfaces(self,**params):
        self.calls.append(('ec2','DescribeNetworkInterfaces',params))
        identifier=params['NetworkInterfaceIds'][0];src=identifier==SRC
        return {'NetworkInterfaces':[{'NetworkInterfaceId':identifier,'Status':'in-use','VpcId':VPC if src else self.destination_vpc,'SubnetId':S1 if src else S2,
                 'PrivateIpAddress':'10.0.1.10' if src else '10.0.2.10','Groups':[{'GroupId':SG1 if src else SG2}]}]}
    def describe_route_tables(self,**params):
        self.calls.append(('ec2','DescribeRouteTables',params))
        if self.main and params['Filters'][0]['Name']=='association.subnet-id':return {'RouteTables':[]}
        route={'DestinationCidrBlock':'10.0.0.0/16','State':'blackhole' if self.blackhole else 'active'}
        route.update({'VpcPeeringConnectionId':'pcx-00000001'} if self.peer else {'TransitGatewayId':'tgw-00000001'} if self.tgw else {'NatGatewayId':'nat-00000001'} if self.nat else {'GatewayId':'local'})
        return {'RouteTables':[{'RouteTableId':'rtb-00000001','Routes':[route]}]}
    def describe_security_groups(self,**params):
        self.calls.append(('ec2','DescribeSecurityGroups',params));groups=[]
        for identifier in params['GroupIds']:
            groups.append({'GroupId':identifier,'IpPermissionsEgress':[{'IpProtocol':'-1','IpRanges':[{'CidrIp':'0.0.0.0/0'}]}],
              'IpPermissions':[{'IpProtocol':'tcp','FromPort':443,'ToPort':443,'UserIdGroupPairs':[{'GroupId':SG1}]}] if self.ingress else []})
        return {'SecurityGroups':groups}
    def describe_network_acls(self,**params):
        self.calls.append(('ec2','DescribeNetworkAcls',params));rules=[]
        for egress in (False,True):
            if self.return_deny:rules.append({'RuleNumber':50,'Egress':egress,'Protocol':'6','CidrBlock':'0.0.0.0/0','RuleAction':'deny','PortRange':{'From':50000,'To':65535}})
            rules.append({'RuleNumber':100,'Egress':egress,'Protocol':'-1','CidrBlock':'0.0.0.0/0','RuleAction':'allow'})
        return {'NetworkAcls':[{'NetworkAclId':'acl-00000001','Entries':rules}]}
    def describe_vpc_peering_connections(self,**params):
        self.calls.append(('ec2','DescribeVpcPeeringConnections',params))
        return {'VpcPeeringConnections':[{'Status':{'Code':'active' if self.peer_active else 'pending-acceptance'},'RequesterVpcInfo':{'VpcId':VPC},'AccepterVpcInfo':{'VpcId':self.destination_vpc}}]}
    def describe_transit_gateway_attachments(self,**params):
        self.calls.append(('ec2','DescribeTransitGatewayAttachments',params))
        return {'TransitGatewayAttachments':[{'TransitGatewayAttachmentId':a,'ResourceId':v,'ResourceType':'vpc','State':'available','Association':{'State':'associated','TransitGatewayRouteTableId':r}} for a,v,r in [('tgw-attach-00000001',VPC,'tgw-rtb-00000001'),('tgw-attach-00000002',self.destination_vpc,'tgw-rtb-00000002')]]}
    def search_transit_gateway_routes(self,**params):
        self.calls.append(('ec2','SearchTransitGatewayRoutes',params))
        dest='tgw-attach-00000002' if params['TransitGatewayRouteTableId']=='tgw-rtb-00000001' else 'tgw-attach-00000001'
        return {'Routes':[{'State':'blackhole' if self.tgw_blackhole else 'active','TransitGatewayAttachments':[{'TransitGatewayAttachmentId':dest}]}]}


def tool(ec2):
    session=MagicMock();session.client.return_value=ec2
    return Network(EvidenceStore(),factory=lambda *a:(session,None))


def test_longest_prefix_blackhole_overrides_default():
    r=longest_route([{'DestinationCidrBlock':'0.0.0.0/0','State':'active','GatewayId':'igw-a'},
                     {'DestinationCidrBlock':'10.0.0.0/16','State':'blackhole','VpcPeeringConnectionId':'pcx-a'}],'10.0.1.10')
    assert r['assessment']=='blackhole'
    assert longest_route([], '10.0.1.10')['assessment']=='no_route'


def test_prefix_unknown_and_equal_prefix_ambiguity():
    routes=[{'DestinationPrefixListId':'pl-a','State':'active','GatewayId':'vpce-a'}]
    assert longest_route(routes,'10.0.1.10')['assessment']=='unknown_prefix_list_route'
    assert longest_route(routes,'10.0.1.10',{'pl-a':['10.0.0.0/16']})['assessment']=='route_observed'
    assert longest_route([{'DestinationCidrBlock':'0.0.0.0/0','GatewayId':k,'State':'active'} for k in ('a','b')],'10.0.1.10')['assessment']=='ambiguous_equal_prefix_routes'


def test_security_group_union_and_stateful_scope():
    groups=[{'GroupId':SG1,'IpPermissions':[]},{'GroupId':SG2,'IpPermissions':[{'IpProtocol':'-1','IpRanges':[{'CidrIp':'10.0.0.0/8'}]}]}]
    assert sg_decision(groups,'ingress','10.0.1.10',set(),'tcp',443)['assessment']=='allow_rule_observed'
    assert sg_decision(groups,'ingress','192.168.1.1',set(),'tcp',443)['assessment']=='no_allow_rule'
    groups=[{'GroupId':SG2,'IpPermissions':[{'IpProtocol':'tcp','FromPort':443,'ToPort':443,'UserIdGroupPairs':[{'GroupId':SG1}]}]}]
    assert sg_decision(groups,'ingress','10.0.1.10',{SG1},'tcp',443,False)['assessment']=='unknown_reference_support'


def test_nacl_priority_and_ephemeral_split():
    rules=[{'RuleNumber':200,'Egress':True,'Protocol':'-1','CidrBlock':'0.0.0.0/0','RuleAction':'allow'},
           {'RuleNumber':100,'Egress':True,'Protocol':'6','CidrBlock':'10.0.0.0/8','RuleAction':'deny','PortRange':{'From':50000,'To':65535}}]
    assert nacl_one(rules,True,'10.0.1.1','tcp',60000)['action']=='deny'
    assert nacl_one(rules,True,'10.0.1.1','tcp',443)['action']=='allow'
    assert nacl_range(rules,True,'10.0.1.1','tcp',1024,65535)['assessment']=='mixed_or_unknown'
    assert nacl_one([],False,'10.0.1.1','tcp',443)['implicit']


def test_same_vpc_path_and_main_fallback(configured):
    e=EC2();e.main=True
    r=tool(e).query('test','us-east-1','path',**PARAMS)
    assert r['summary']['assessment']=='configuration_consistent'
    assert r['coverage']['complete'] and not r['summary']['connection_verified']
    assert len([x for x in e.calls if x[1]=='DescribeRouteTables'])==4


@pytest.mark.parametrize('flag',['ingress','blackhole'])
def test_known_configuration_block(configured,flag):
    e=EC2();setattr(e,flag,False if flag=='ingress' else True)
    r=tool(e).query('test','us-east-1','path',**PARAMS)
    assert r['summary']['assessment']=='configuration_blocked' and r['status']=='degraded'


def test_unknown_return_port_does_not_claim_connection_block(configured):
    e=EC2();e.return_deny=True
    r=tool(e).query('test','us-east-1','path',**PARAMS)
    assert r['summary']['assessment']=='insufficient_evidence'
    assert r['status']=='partial'
    r=tool(e).query('test','us-east-1','path',**PARAMS,source_port=60000)
    assert r['summary']['assessment']=='configuration_blocked'


def test_nat_not_traced(configured):
    e=EC2();e.nat=True;e.ingress=False
    r=tool(e).query('test','us-east-1','path',**PARAMS)
    assert r['summary']['assessment']=='insufficient_evidence'


def test_peer_active_and_wrong_state(configured):
    e=EC2();e.peer=True;e.destination_vpc='vpc-00000002'
    r=tool(e).query('test','us-east-1','path',**PARAMS)
    assert r['summary']['assessment']=='configuration_consistent'
    e.peer_active=False
    r=tool(e).query('test','us-east-1','path',**PARAMS)
    assert r['summary']['assessment']=='configuration_blocked'


def test_tgw_route_not_complete_path(configured):
    e=EC2();e.tgw=True;e.destination_vpc='vpc-00000002'
    r=tool(e).query('test','us-east-1','path',**PARAMS)
    assert r['status']=='partial' and r['summary']['assessment']=='insufficient_evidence'
    assert len([i for i in r['items'] if i['kind']=='network_tgw_route'])==2
    e.tgw_blackhole=True
    r=tool(e).query('test','us-east-1','path',**PARAMS)
    assert r['summary']['assessment']=='configuration_blocked'


def test_prefix_delegated_ip_and_invalid_ip(configured):
    e={'PrivateIpAddress':'10.0.1.10','Ipv4Prefixes':[{'Ipv4Prefix':'10.0.2.0/28'}]}
    assert Network.address(e,'10.0.2.12')=='10.0.2.12'
    with pytest.raises(CollectionError,match='ip_not_attached'):Network.address(e,'10.0.5.1')
    with pytest.raises(ValueError):Network.address(e,'::1')


def test_cross_account_aliases_resolved_and_isolated(monkeypatch):
    from aws_ops_mcp.config import Account
    monkeypatch.setattr('aws_ops_mcp.network.resolve',lambda alias,region:Account(account_id={'test':'000000000000','dest':'111111111111','net':'222222222222'}[alias],regions=[region]))
    e=EC2();seen=[]
    def factory(config,region):
        seen.append(config.account_id);s=MagicMock();s.client.return_value=e;return s,None
    r=Network(EvidenceStore(),factory=factory).query('test','us-east-1','path',**PARAMS,destination_account='dest',network_account='net')
    assert r['summary']['assessment']=='configuration_consistent'
    assert seen==['000000000000','111111111111','222222222222']


def test_no_raw_api_or_log_secrets(configured):
    e=EC2()
    def denied(**kwargs):raise ClientError({'Error':{'Code':'AccessDenied','Message':'NEVER_RETURN'}},'DescribeRouteTables')
    e.describe_route_tables=denied
    r=tool(e).query('test','us-east-1','path',**PARAMS)
    assert r['status']=='partial' and r['errors'][0]['code']=='access_denied'
    assert 'NEVER_RETURN' not in json.dumps(r)


def record(action='ACCEPT',status='OK'):
    return f'2 000000000000 {SRC} 10.0.1.10 10.0.2.10 51000 443 6 10 400 1767225600 1767225660 {action} {status}'


def flow_tool(records,token=None):
    client=MagicMock();client.filter_log_events.return_value={'events':[{'eventId':str(i),'message':r} for i,r in enumerate(records)]}
    if token:client.filter_log_events.return_value['nextToken']=token
    return tool(client),client


FLOW={'log_group_name':'/vpc/flows','start_time':'2026-01-01T00:00:00Z','end_time':'2026-01-01T00:10:00Z','interface_id':SRC}


def test_flows_accept_reject_metadata_only(configured):
    t,c=flow_tool([record(),record('REJECT')])
    r=t.query('test','us-east-1','flows',**FLOW)
    assert r['summary']['actions']=={'ACCEPT':1,'REJECT':1}
    assert not r['coverage']['history_complete']
    assert all('message' not in x for x in r['items'])
    assert not r['summary']['connection_verified']


@pytest.mark.parametrize('status',['SKIPDATA','NODATA'])
def test_skipdata_and_nodata_not_zero_traffic(configured,status):
    t,_=flow_tool([record(status=status)])
    r=t.query('test','us-east-1','flows',**FLOW)
    assert r['summary']['matched']==0
    if status=='SKIPDATA':assert r['status']=='partial'
    assert r['summary']['assessment']=='no_matching_retained_record'


def test_malformed_foreign_account_and_payload_not_returned(configured):
    t,_=flow_tool(['password=NEVER_RETURN',record().replace('000000000000','111111111111')])
    r=t.query('test','us-east-1','flows',**FLOW)
    assert r['summary']['other_account_records_omitted']==1
    assert r['status']=='partial' and 'NEVER_RETURN' not in json.dumps(r)
    assert parse_flow(record().replace('10.0.1.10','bad')) is None


def test_flow_filters_and_timestamp_window(configured):
    t,_=flow_tool([record()])
    r=t.query('test','us-east-1','flows',**FLOW,destination_ip='10.0.5.1',port=443)
    assert r['summary']['matched']==0
    assert parse_flow(record())['destination_port']==443


def test_flow_cycle_limits_and_invalid_inputs(configured):
    t,_=flow_tool([record()],token='repeat')
    r=t.query('test','us-east-1','flows',**FLOW)
    assert r['errors'][0]['code']=='network_pagination_cycle'
    assert r['status']=='partial'
    r=t.query('test','us-east-1','flows',**dict(FLOW,end_time='2026-01-02T00:00:00Z'))
    assert r['errors'][0]['code']=='flow_window_positive_max_1h'
    r=t.query('test','us-east-1','path',**dict(PARAMS,port=0))
    assert r['errors'][0]['code']=='invalid_destination_port'


def test_context_deadline_before_call(configured):
    now=[0];c=Context(lambda *a:(_ for _ in ()).throw(AssertionError('should not authenticate')),'us-east-1',lambda:now[0])
    now[0]=46
    with pytest.raises(CollectionError,match='deadline'):c.call('test','ec2','describe_vpcs')


def test_sdk_parameters_against_botocore(configured):
    import botocore.session
    from botocore.validate import validate_parameters
    models=botocore.session.get_session();e=EC2();e.peer=True;e.destination_vpc='vpc-00000002'
    tool(e).query('test','us-east-1','path',**PARAMS)
    e.peer=False;e.tgw=True;tool(e).query('test','us-east-1','path',**PARAMS)
    for service,method,params in e.calls:validate_parameters(params,models.get_service_model(service).operation_model(method).input_shape)
    t,c=flow_tool([record()]);t.query('test','us-east-1','flows',**FLOW)
    validate_parameters(c.filter_log_events.call_args.kwargs,models.get_service_model('logs').operation_model('FilterLogEvents').input_shape)


def test_prefix_list_expansion_and_cycle(configured):
    from unittest.mock import MagicMock
    client=MagicMock();client.get_managed_prefix_list_entries.return_value={'Entries':[{'Cidr':'10.0.0.0/16'}]}
    session=MagicMock();session.client.return_value=client
    c=Context(lambda *a:(session,None),'us-east-1',lambda:0)
    assert c.prefix_map('test',{'pl-00000001'})=={'pl-00000001':['10.0.0.0/16']}
    c.prefix_map('test',{'pl-00000001'});assert client.get_managed_prefix_list_entries.call_count==1
    client.get_managed_prefix_list_entries.return_value={'Entries':[],'NextToken':'repeat'}
    with pytest.raises(CollectionError,match='pagination_cycle'):c.prefix_map('test',{'pl-00000002'})
    import botocore.session
    from botocore.validate import validate_parameters
    model=botocore.session.get_session().get_service_model('ec2')
    validate_parameters(client.get_managed_prefix_list_entries.call_args.kwargs,model.operation_model('GetManagedPrefixListEntries').input_shape)


def test_flow_match_limit_preserves_evidence(configured):
    t,_=flow_tool([record() for _ in range(201)])
    r=t.query('test','us-east-1','flows',**FLOW)
    assert r['status']=='partial' and r['errors'][0]['code']=='flow_match_limit'
    assert r['evidence_id']
    assert not r['coverage']['complete']


def test_flow_window_offset_and_ipv6_rejected(configured):
    t,_=flow_tool([])
    r=t.query('test','us-east-1','flows',**dict(FLOW,start_time='2026-01-01T00:00:00'))
    assert r['errors'][0]['code']=='invalid_time_requires_offset'
    r=t.query('test','us-east-1','path',**PARAMS,source_ip='::1')
    assert r['errors'][0]['code']=='ipv4_required'
