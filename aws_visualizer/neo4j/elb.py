import os
import boto3
from neomodel import *
import logging

from .security_group import SecurityGroup
from .ec2_instance import EC2Instance
from .sts import get_account_id_and_region

class ElasticLoadBalancer(StructuredNode):
    Name = StringProperty()
    ARN = StringProperty(unique_index=True)
    SecurityGroups = Relationship('SecurityGroup', 'APPLIED')
    Backends = Relationship('EC2Instance', 'BACKEND')
    VpcId = StringProperty()

    @staticmethod
    def arn(region, owner_id, name):
        return 'arn:aws:elasticloadbalancing:{}:{}:loadbalancer/{}'.format(region, owner_id, name)


def load():
    elb = boto3.client('elb')
    OwnerId, AWSRegion = get_account_id_and_region()
    paginator = elb.get_paginator('describe_load_balancers')
    for page in paginator.paginate():
        for lb in page['LoadBalancerDescriptions']:
            name = lb['LoadBalancerName']
            arn = ElasticLoadBalancer.arn(AWSRegion, OwnerId, name)
            properties = { 'Name': name, 'ARN': arn, 'OwnerId': OwnerId, 'VpcId': lb['VPCId'] if 'VPCId' in lb else None}
            loadbalancer = ElasticLoadBalancer.create_or_update(properties)[0]
            sys.stderr.write('INFO: loading classic elb {}\n'.format(name))

            for group in loadbalancer.SecurityGroups:
                loadbalancer.SecurityGroups.disconnect(group)

            for instance in loadbalancer.Backends:
                loadbalancer.Backends.disconnect(instance)

            for GroupId in lb['SecurityGroups']:
                group = SecurityGroup.get_or_create({'ARN': SecurityGroup.arn(AWSRegion, OwnerId, GroupId)})[0]
                sys.stderr.write('INFO: applying security group {} to elb {}\n'.format(group.GroupId, name))
                loadbalancer.SecurityGroups.connect(group)

            for InstanceId in map(lambda i: i['InstanceId'], lb['Instances']):
                arn = EC2Instance.arn(AWSRegion, OwnerId, InstanceId)
                instance = EC2Instance.get_or_create({'ARN': arn, 'InstanceId': InstanceId, 'OwnerId': OwnerId})[0]
                sys.stderr.write('INFO: adding instance {} as backed to elb {}\n'.format(InstanceId, name))
                loadbalancer.Backends.connect(instance)

