import os
import boto3
from neomodel import *
import logging

from .sts import get_account_id_and_region
from .security_group import SecurityGroup
from .elb import ElasticLoadBalancer


def load():
    elb = boto3.client('elbv2')
    OwnerId, AWSRegion = get_account_id_and_region()
    paginator = elb.get_paginator('describe_load_balancers')
    for page in paginator.paginate():
        for lb in page['LoadBalancers']:
            name = lb['LoadBalancerName']
            arn = lb['LoadBalancerArn']
            properties = { 'Name': name, 'ARN': arn, 'OwnerId': OwnerId, 'VpcId': lb['VpcId']}
            loadbalancer = ElasticLoadBalancer.create_or_update(properties)[0]
            sys.stderr.write('INFO: loading elb v2 {}\n'.format(name))

            for group in loadbalancer.SecurityGroups:
                loadbalancer.SecurityGroups.disconnect(group)

            for GroupId in lb['SecurityGroups']:
                group = SecurityGroup.get_or_create({'ARN': SecurityGroup.arn(AWSRegion, OwnerId, GroupId)})[0]
                sys.stderr.write('INFO: applying security group {} to elb v2 {}\n'.format(group.GroupId, name))
                loadbalancer.SecurityGroups.connect(group)
