import os
import boto3
from neomodel import *
import logging

from .sts import get_account_id_and_region
from .security_group import SecurityGroup


class RedshiftCluster(StructuredNode):
    DBName = StringProperty()
    ClusterIdentifier = StringProperty()
    ARN = StringProperty(unique_index=True)
    SecurityGroups = RelationshipFrom('SecurityGroup', 'APPLIED')
    OwnerId = StringProperty()
    VpcId = StringProperty()

    @staticmethod
    def arn(region, owner_id, cluster_id):
        return 'arn:aws:redshift:{}:{}:cluster/{}'.format(region, owner_id, cluster_id)

def load():
    redshift = boto3.client('redshift')
    OwnerId, AWSRegion = get_account_id_and_region()
    paginator = redshift.get_paginator('describe_clusters')
    for page in paginator.paginate():
        for db in page['Clusters']:
            name = db['ClusterIdentifier']
            DBName = db['DBName']
            arn = RedshiftCluster.arn(AWSRegion, OwnerId, name)
            properties = { 'DBName': DBName, 'ARN': arn, 'OwnerId': OwnerId,
                           'VpcId': db['VpcId'], 'ClusterInstanceIdentifier': name}
            cluster = RedshiftCluster.create_or_update(properties)[0]
            sys.stderr.write('INFO: loading redshift cluster {}\n'.format(name))

            # remove old associations
            for group in cluster.SecurityGroups:
                cluster.SecurityGroups.disconnect(group)

            for GroupId in map(lambda g: g['VpcSecurityGroupId'], db['VpcSecurityGroups']):
                group = SecurityGroup.get_or_create({'ARN': SecurityGroup.arn(AWSRegion, OwnerId, GroupId)})[0]
                sys.stderr.write('INFO: applying security group {} to cluster {}\n'.format(group.GroupId, name))
                cluster.SecurityGroups.connect(group)

