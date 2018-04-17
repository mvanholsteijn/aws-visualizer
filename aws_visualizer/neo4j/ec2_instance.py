import os
import boto3
from neomodel import *
import logging
from .security_group import SecurityGroup


class EC2Instance(StructuredNode):
    Name = StringProperty()
    ARN = StringProperty(unique_index=True)
    OwnerId = StringProperty()
    InstanceId = StringProperty()
    SecurityGroups = Relationship('SecurityGroup', 'APPLIED')
    VpcId = StringProperty()

    @staticmethod
    def arn(region, owner_id, instance_id):
        return 'arn::ec2:{}:{}:instance/{}'.format(region, owner_id, instance_id)

def get_instance_name(obj):
    return next(map(lambda t: t['Value'], list(filter(lambda t: t['Key'] == 'Name', obj['Tags'] if 'Tags' in obj else {}))), obj['InstanceId'])

def get_account_id_and_region():
    sts = boto3.client('sts')
    return sts.get_caller_identity()['Account'], sts.meta.region_name

def load():
    ec2 = boto3.client('ec2')
    OwnerId, AWSRegion = get_account_id_and_region()
    paginator = ec2.get_paginator('describe_instances')
    for page in paginator.paginate():
        for r in page['Reservations']:
            for i in filter(lambda i: i['State']['Name'] != "terminated", r['Instances']):
                InstanceId = i['InstanceId']
                arn = EC2Instance.arn(AWSRegion, OwnerId, InstanceId)
                name = get_instance_name(i)
                instance = EC2Instance.create_or_update({'ARN': arn, 'Name': get_instance_name(i), 'InstanceId': InstanceId, 'OwnerId': OwnerId})[0]
                sys.stderr.write('INFO: loading ec2 instance {}\n'.format(InstanceId))

                # remove old associations
                for group in instance.SecurityGroups:
                    instance.SecurityGroups.disconnect(group)

                for sg in i['SecurityGroups']:
                    group = SecurityGroup.get_or_create({'ARN': SecurityGroup.arn(ec2.meta.region_name, OwnerId, sg['GroupId'])})[0]
                    sys.stderr.write('INFO: applying security group {} to ec2 instance {}\n'.format(group.GroupId, InstanceId))
                    instance.SecurityGroups.connect(group)

