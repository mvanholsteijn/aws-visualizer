import os
import boto3
from neomodel import *
import logging


from .sts import get_account_id_and_region
from .security_group import SecurityGroup

class DBInstance(StructuredNode):
    DBName = StringProperty()
    DBInstanceIdentifier = StringProperty()
    ARN = StringProperty(unique_index=True)
    SecurityGroups = RelationshipFrom('SecurityGroup', 'APPLIED')
    OwnerId = StringProperty()
    VpcId = StringProperty()

def load():
    rds = boto3.client('rds')
    OwnerId, AWSRegion = get_account_id_and_region()
    paginator = rds.get_paginator('describe_db_instances')
    for page in paginator.paginate():
        for db in page['DBInstances']:
            name = db['DBInstanceIdentifier']
            DBName = db['DBName']
            arn = db['DBInstanceArn']
            properties = { 'DBName': DBName, 'ARN': arn, 'OwnerId': OwnerId,
                           'VpcId': db['DBSubnetGroup']['VpcId'], 'DBInstanceIdentifier': name}
            db_instance = DBInstance.create_or_update(properties)[0]
            sys.stderr.write('INFO: loading rds instance {}\n'.format(name))

            # remove old associations
            for group in db_instance.SecurityGroups:
                db_instance.SecurityGroups.disconnect(group)

            for GroupId in map(lambda g: g['VpcSecurityGroupId'], db['VpcSecurityGroups']):
                group = SecurityGroup.get_or_create({'ARN': SecurityGroup.arn(AWSRegion, OwnerId, GroupId)})[0]
                sys.stderr.write('INFO: applying security group {} to rds {}\n'.format(group.GroupId, name))
                db_instance.SecurityGroups.connect(group)
