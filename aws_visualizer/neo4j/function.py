import os
import boto3
from neomodel import *
import logging

from .sts import get_account_id_and_region
from .security_group import SecurityGroup
from .elb import ElasticLoadBalancer


class Function(StructuredNode):
    Name = StringProperty()
    ARN = StringProperty(unique_index=True)
    SecurityGroups = RelationshipFrom('SecurityGroup', 'APPLIED')
    OwnerId = StringProperty()
    VpcId = StringProperty()

    @staticmethod
    def arn(region, owner_id, name):
        return 'arn:aws:elasticloadbalancing:{}:{}:loadbalancer/{}'.format(region, owner_id, name)

def load():
    awslambda = boto3.client('lambda')
    OwnerId, AWSRegion = get_account_id_and_region()
    paginator = awslambda.get_paginator('list_functions')
    for page in paginator.paginate():
        for f in filter(lambda f: 'VpcConfig' in f and f['VpcConfig']['VpcId'] != '', page['Functions']):
            name = f['FunctionName']
            arn = f['FunctionArn']
            properties = { 'Name': name, 'ARN': arn, 'OwnerId': OwnerId, 'VpcId':  f['VpcConfig']['VpcId']}
            function = Function.create_or_update(properties)[0]
            sys.stderr.write('INFO: loading function {}\n'.format(name))

            # remove old associations
            for group in function.SecurityGroups:
                function.SecurityGroups.disconnect(group)

            for GroupId in f['VpcConfig']['SecurityGroupIds']:
                group = SecurityGroup.get_or_create({'ARN': SecurityGroup.arn(AWSRegion, OwnerId, GroupId)})[0]
                sys.stderr.write('INFO: applying security group {} to function {}\n'.format(group.GroupId, name))
                function.SecurityGroups.connect(group)

