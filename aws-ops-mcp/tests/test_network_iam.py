import json
import time
from datetime import datetime, timezone
from urllib.parse import quote
from unittest.mock import MagicMock

import pytest
import botocore.session
from botocore.exceptions import ClientError
from botocore.validate import validate_parameters

from aws_ops_mcp.platform_ops import Platform, OperationsJobs
from aws_ops_mcp.evidence import EvidenceStore
from aws_ops_mcp.policy_analysis import query, analyze
from aws_ops_mcp.ops_runtime import ReadContext
from aws_ops_mcp.eks_cli import CollectionError

VPC='vpc-00000001';PEER='vpc-00000002'
ALLOW={'Version':'2012-10-17','Statement':[{'Effect':'Allow','Action':'*','Resource':'*'}]}
TRUST={'Statement':[{'Effect':'Allow','Action':'sts:AssumeRole','Principal':{'Service':'ec2.amazonaws.com'}}]}


class APIs:
    def __init__(self):self.deny=False;self.policy_calls=0;self.secrets='DO_NOT_RETURN_SECRET'
    def describe_vpcs(self,**p):return {'Vpcs':[{'VpcId':v,'CidrBlock':'10.0.0.0/16','State':'available','Ipv6CidrBlockAssociationSet':[
        {'Ipv6CidrBlock':'2001:db8::/56','Ipv6CidrBlockState':{'State':'associated'}}]} for v in [VPC,PEER]]}
    def describe_vpc_attribute(self,**p):return {p['Attribute'][0].upper()+p['Attribute'][1:]:{'Value':True}}
    def describe_subnets(self,**p):return {'Subnets':[{'SubnetId':'subnet-00000001','VpcId':VPC,'CidrBlock':'10.0.1.0/24','AvailabilityZone':'us-east-1a','MapPublicIpOnLaunch':True}]}
    def describe_route_tables(self,**p):return {'RouteTables':[{'RouteTableId':'rtb-00000001','VpcId':VPC,'Routes':[{'State':'blackhole','DestinationCidrBlock':'10.1.0.0/16','TransitGatewayId':'tgw-00000001'}]}]}
    def describe_nat_gateways(self,**p):
        if self.deny:raise ClientError({'Error':{'Code':'AccessDenied','Message':self.secrets}},'DescribeNatGateways')
        return {'NatGateways':[{'NatGatewayId':'nat-00000001','VpcId':VPC,'State':'failed'}]}
    def describe_internet_gateways(self,**p):return {'InternetGateways':[]}
    def describe_vpc_endpoints(self,**p):return {'VpcEndpoints':[{'VpcEndpointId':'vpce-00000001','VpcId':VPC,'State':'rejected','PolicyDocument':self.secrets}]}
    def describe_vpc_peering_connections(self,**p):return {'VpcPeeringConnections':[]}
    def describe_transit_gateway_vpc_attachments(self,**p):return {'TransitGatewayVpcAttachments':[]}
    def describe_security_groups(self,**p):return {'SecurityGroups':[{'GroupId':'sg-00000001','IpPermissions':[
        {'IpProtocol':'-1','Ipv6Ranges':[{'CidrIpv6':'::/0'}]}]}]}
    def describe_vpn_connections(self,**p):return {'VpnConnections':[{'VpnConnectionId':'vpn-00000001','State':'available',
        'CustomerGatewayConfiguration':self.secrets,'Options':{'TunnelOptions':[{'PreSharedKey':self.secrets}]},
        'VgwTelemetry':[{'Status':'DOWN','AcceptedRouteCount':0,'LastStatusChange':datetime.now(timezone.utc)}]}]}
    def describe_connections(self,**p):return {'connections':[{'connectionId':'dxcon-demo','connectionState':'down'}]}
    def get_role(self,**p):return {'Role':{'Arn':'arn:aws:iam::000000000000:role/demo','AssumeRolePolicyDocument':TRUST,
        'PermissionsBoundary':{'PermissionsBoundaryArn':'arn:aws:iam::000000000000:policy/boundary'},'MaxSessionDuration':3600}}
    def list_role_policies(self,**p):return {'PolicyNames':['demo'], 'IsTruncated':False}
    def get_role_policy(self,**p):return {'PolicyDocument':ALLOW}
    def list_attached_role_policies(self,**p):return {'AttachedPolicies':[{'PolicyArn':'arn:aws:iam::000000000000:policy/demo'}],'IsTruncated':False}
    def get_policy(self,**p):return {'Policy':{'DefaultVersionId':'v1'}}
    def get_policy_version(self,**p):
        self.policy_calls+=1
        if self.deny:raise ClientError({'Error':{'Code':'AccessDenied','Message':self.secrets}},'GetPolicyVersion')
        return {'PolicyVersion':{'Document':ALLOW}}
    def get_hosted_zone(self,**p):return {'HostedZone':{'Name':'example.test.','Config':{'PrivateZone':False}},'DelegationSet':{'NameServers':['ns.example.test']}}
    def list_resource_record_sets(self,**p):return {'ResourceRecordSets':[
        {'Name':'www.example.test.','Type':'A','AliasTarget':{'DNSName':'demo.cloudfront.net.','HostedZoneId':'Z2FDTNDATAQYW2','EvaluateTargetHealth':False}},
        {'Name':'www.example.test.','Type':'TXT','TTL':300,'ResourceRecords':[{'Value':self.secrets}]}], 'IsTruncated':False}


def tool(api):
    session=MagicMock();session.client.return_value=api
    return Platform(EvidenceStore(),factory=lambda *args:(session,None)),session


def codes(result):return {f['code'] for f in result['findings']}


def test_wildcards_denies_and_conditions_do_not_claim_effective_access():
    result=query(json.dumps(ALLOW))
    assert result['status']=='degraded' and codes(result)=={'allow_all_actions_resources'}
    assert not result['summary']['effective_authorization_verified']
    doc={'Statement':[{'Effect':'Deny','Action':'*','Resource':'*'},{'Effect':'Allow','Action':'*','Resource':'*','Condition':{'StringEquals':{'secret:key':'SECRET'}}}]}
    result=query(json.dumps(doc))
    assert len(result['findings'])==1 and result['findings'][0]['severity']=='warning'
    assert 'SECRET' not in json.dumps(result) and 'secret:key' not in json.dumps(result)


def test_notaction_notresource_principal_signals():
    doc={'Statement':{'Effect':'Allow','NotAction':'iam:*','NotResource':'arn:aws:s3:::demo','Principal':'*'}}
    result=query(json.dumps(doc),'resource')
    assert {'allow_not_action_requires_review','allow_not_resource_requires_review','allow_wildcard_principal'}<=codes(result)


@pytest.mark.parametrize('doc', ['not json','[]','{}','{"Statement":[]}',json.dumps({'Statement':{'Effect':'Allow','Action':'*','NotAction':'s3:*','Resource':'*'}}),json.dumps({'Statement':{'Effect':'Allow','Action':'*'}})])
def test_invalid_documents_safe_error(doc):
    result=query(doc)
    assert result['status']=='error' and not result['coverage']['complete']


def test_oidc_constraints_are_observed_without_subject_values():
    statement={'Effect':'Allow','Action':'sts:AssumeRoleWithWebIdentity','Principal':{'Federated':'arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com'}}
    result=query(json.dumps({'Statement':statement}),'trust')
    assert codes(result)=={'oidc_audience_constraint_not_observed','oidc_subject_constraint_not_observed'}
    statement['Condition']={'StringEquals':{'token.actions.githubusercontent.com:aud':'sts.amazonaws.com'},
        'StringLike':{'token.actions.githubusercontent.com:sub':'repo:private/project:*'}}
    result=query(json.dumps({'Statement':statement}),'trust')
    assert not result['findings'] and 'private/project' not in json.dumps(result)


def test_url_encoded_sdk_policy_and_size_limit():
    rows,findings=analyze(quote(json.dumps(ALLOW)))
    assert len(rows)==1 and findings
    assert query(' '*32769)['errors'][0]['code']=='policy_size_limit'


def test_role_attached_inline_boundary_global_endpoint(configured):
    api=APIs();platform,session=tool(api)
    result=platform.query('test','us-east-1','iam_role',role_name='demo')
    assert result['status']=='degraded' and not result['summary']['effective_authorization_verified']
    assert result['summary']['boundary_present'] and result['summary']['attached_policies']==1
    assert api.policy_calls==2
    session.client.assert_called_once_with('iam',region_name='us-east-1',config=None)
    assert 'AssumeRolePolicyDocument' not in json.dumps(result)


def test_role_denied_policy_preserves_other_evidence(configured):
    api=APIs();api.deny=True;platform,_=tool(api)
    result=platform.query('test','us-east-1','iam_role',role_name='demo')
    assert result['status']=='partial' and result['evidence_id']
    assert result['errors'][0]['code']=='access_denied' and api.secrets not in json.dumps(result)


def test_role_input_rejected_before_aws(configured):
    api=APIs();platform,session=tool(api)
    result=platform.query('test','us-east-1','iam_role',role_name='bad;command')
    assert result['errors'][0]['code']=='invalid_role_name'
    session.client.assert_not_called()


def test_regional_topology_overlaps_ipv6_public_rules_and_no_tunnel_secrets(configured):
    api=APIs();platform,session=tool(api)
    result=platform.query('test','us-east-1','network',include_hybrid=True)
    assert result['status']=='degraded' and result['coverage']['complete']
    assert {'vpc_cidr_overlap','route_blackhole','nat_gateway_failed','vpc_endpoint_unavailable','public_ingress_rule_observed','vpn_tunnel_down'}<=codes(result)
    assert not result['summary']['connectivity_verified']
    saved=platform.store.get(result['evidence_id'])
    assert api.secrets not in json.dumps(saved)
    assert session.client.call_args_list[0].kwargs['region_name']=='us-east-1'
    assert next(f for f in result['findings'] if f['code']=='public_ingress_rule_observed')['confidence']=='possible'


def test_topology_component_denied_does_not_erase_other_checks(configured):
    api=APIs();api.deny=True;platform,_=tool(api)
    result=platform.query('test','us-east-1','network')
    assert result['status']=='partial' and 'route_blackhole' in codes(result)
    assert result['errors'][0]['code']=='access_denied'


def test_topology_selection_bounds_and_empty_inventory(configured):
    api=APIs();platform,session=tool(api)
    result=platform.query('test','us-east-1','network',vpc_ids=['bad'])
    assert result['errors'][0]['code']=='invalid_vpc_selection'
    session.client.assert_not_called()
    api.describe_vpcs=lambda **p:{'Vpcs':[]}
    assert platform.query('test','us-east-1','network')['errors'][0]['code']=='no_vpcs_observed'


def test_dns_metadata_only_and_outside_zone(configured):
    api=APIs();platform,_=tool(api)
    result=platform.query('test','us-east-1','dns',hosted_zone_id='ZDEMO',record_name='www.example.test')
    assert result['status']=='ok' and result['summary']['observed_matching_records']==2
    assert not result['summary']['resolution_verified'] and api.secrets not in json.dumps(result)
    record=next(r for r in result['items'] if r['kind']=='dns_record' and r['type']=='TXT')
    assert record['values_omitted'] and 'values' not in record
    invalid=platform.query('test','us-east-1','dns',hosted_zone_id='ZDEMO',record_name='evil.test')
    assert invalid['errors'][0]['code']=='record_outside_hosted_zone'


def test_dns_exact_name_no_record_is_not_resolution_claim(configured):
    api=APIs();platform,_=tool(api)
    api.list_resource_record_sets=lambda **p:{'ResourceRecordSets':[],'IsTruncated':False}
    result=platform.query('test','us-east-1','dns',hosted_zone_id='ZDEMO',record_name='absent.example.test')
    assert result['summary']['assessment']=='no_exact_record_observed' and not result['summary']['resolution_verified']


def test_iam_pagination_marker_cycles_and_missing_token(configured):
    api=APIs();platform,_=tool(api);context=ReadContext('test','us-east-1',platform.factory)
    api.list_role_policies=lambda **p:{'PolicyNames':[],'IsTruncated':True,'Marker':'same'}
    with pytest.raises(CollectionError,match='pagination_cycle'):list(context.pages('iam','list_role_policies','PolicyNames',RoleName='demo'))
    api.list_role_policies=lambda **p:{'PolicyNames':[],'IsTruncated':True}
    with pytest.raises(CollectionError,match='pagination_token_missing'):list(context.pages('iam','list_role_policies','PolicyNames',RoleName='demo'))


def test_network_jobs_same_account_different_regions_are_isolated(monkeypatch):
    from aws_ops_mcp.config import Account
    monkeypatch.setattr('aws_ops_mcp.ops_runtime.resolve',lambda *args:Account(account_id='000000000000',regions=['us-east-1','eu-west-1']))
    sessions=[]
    def factory(*args):
        session=MagicMock();session.client.return_value=APIs();sessions.append(session);return session,None
    platform=Platform(EvidenceStore(),factory=factory);jobs=OperationsJobs(platform)
    result=jobs.start([{'account':'test','region':'us-east-1'},{'account':'test','region':'eu-west-1'}],'network')
    for _ in range(100):
        result=jobs.get(result['investigation_id'])
        if result['summary']['state']=='finished':break
        time.sleep(.01)
    assert result['status']=='degraded' and result['coverage']['complete']
    assert {s.client.call_args_list[0].kwargs['region_name'] for s in sessions}=={'us-east-1','eu-west-1'}


def test_sdk_shapes():
    session=botocore.session.get_session()
    filters=[{'Name':'vpc-id','Values':[VPC]}]
    calls=[('ec2','DescribeVpcs',{'VpcIds':[VPC]}),('ec2','DescribeVpcAttribute',{'VpcId':VPC,'Attribute':'enableDnsSupport'}),
        ('ec2','DescribeSubnets',{'Filters':filters}),('ec2','DescribeRouteTables',{'Filters':filters}),
        ('ec2','DescribeNatGateways',{'Filter':filters}),('ec2','DescribeVpcEndpoints',{'Filters':filters}),
        ('ec2','DescribeTransitGatewayVpcAttachments',{'Filters':filters}),('ec2','DescribeVpnConnections',{}),
        ('iam','GetRole',{'RoleName':'demo'}),('iam','ListRolePolicies',{'RoleName':'demo','Marker':'abc'}),
        ('iam','GetRolePolicy',{'RoleName':'demo','PolicyName':'demo'}),('iam','GetPolicyVersion',{'PolicyArn':'arn:aws:iam::000000000000:policy/demo','VersionId':'v1'}),
        ('route53','GetHostedZone',{'Id':'ZDEMO'}),('route53','ListResourceRecordSets',{'HostedZoneId':'ZDEMO','StartRecordName':'example.test.','MaxItems':'100'})]
    for service,name,params in calls:
        shape=session.get_service_model(service).operation_model(name).input_shape
        if shape is not None:validate_parameters(params,shape)
