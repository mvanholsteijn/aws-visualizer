import os
import boto3
from neomodel import *
import logging



class Permission(StructuredRel):
    FromPort = IntegerProperty()
    ToPort = IntegerProperty()
    IpProtocol = StringProperty()

class CIDR(StructuredNode):
    CidrIp = StringProperty(unique=True)
    grants = RelationshipFrom('SecurityGroup', 'GRANTED_BY', model=Permission)

class SecurityGroup(StructuredNode):
    ARN = StringProperty(unique_index=True)
    OwnerId = StringProperty()
    GroupId = StringProperty()
    GroupName = StringProperty()
    VpcIp = StringProperty()
    CidrIpPermissions = RelationshipTo('CIDR', 'GRANTED_TO', model=Permission)
    SecurityGroupPermissions = RelationshipTo('SecurityGroup', 'GRANTED_TO', model=Permission)

    @staticmethod
    def arn(region, owner_id, group_id):
        return 'arn:aws:ec2:{}:{}:security-group/{}'.format(region, owner_id, group_id)


def load():
    log = logging.getLogger()
    groups = {}
    ec2 = boto3.client('ec2')
    paginator = ec2.get_paginator('describe_security_groups')
    pages = paginator.paginate()
    for page in pages:
        for sg in page['SecurityGroups']:
            arn = SecurityGroup.arn(ec2.meta.region_name, sg['OwnerId'], sg['GroupId'])
            groups[arn] = sg

    for arn, sg in groups.items():
        VpcId = sg['VpcId'] if 'VpcId' in sg else None
        properties = {n: sg[n] for n in filter(lambda n: n in sg, ['GroupName', 'OwnerId', 'GroupId', 'VpcId'])}
        properties['ARN'] = arn

        security_group = SecurityGroup.create_or_update(properties)[0]
        sys.stderr.write('storing security group {}\n'.format(security_group.GroupId))

        for p in security_group.CidrIpPermissions:
            security_group.CidrIpPermissions.disconnect(p)
        for p in security_group.SecurityGroupPermissions:
            security_group.SecurityGroupPermissions.disconnect(p)


    for arn, sg in groups.items():
        security_group = SecurityGroup.get_or_create({'ARN': arn})[0]
        for p in sg['IpPermissions']:
            permission = {n : p[n] for n in filter(lambda n : n in p, ['IpProtocol', 'FromPort', 'ToPort'])}
            if VpcId is not None:
                permission['VpcId'] = VpcId

            for c in p['IpRanges']:
                CidrIp = CIDR.get_or_create({'CidrIp': c['CidrIp']})[0]
                security_group.CidrIpPermissions.connect(CidrIp, permission)

            for c in p['Ipv6Ranges']:
                CidrIp = CIDR.get_or_create({'CidrIp': c['CidrIpv6']})[0]
                security_group.CidrIpPermissions.connect(CidrIp, permission)

            for g in p['UserIdGroupPairs']:
                properties = {}
                properties['ARN'] = SecurityGroup.arn(ec2.meta.region_name, g['UserId'], g['GroupId'])
                properties['OwnerId'] = g['UserId']
                properties['GroupId'] = g['GroupId']
                source_sg = SecurityGroup.get_or_create(properties)[0]
                sys.stderr.write('grant IP permission {} from {} to {}\n'.format(permission, security_group.GroupId, source_sg.GroupId))
                security_group.SecurityGroupPermissions.connect(source_sg, permission)


