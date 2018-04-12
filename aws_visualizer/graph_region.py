#!/usr/bin/env python
#   Copyright 2015 Xebia Nederland B.V.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
import argparse

import boto3
from netaddr import IPNetwork, IPAddress
import re
from collections import defaultdict
import sys
import json


class Arc:

    def __init__(self, source, target):
        self.source = source
        self.target = target

    def __repr__(self):
        return '"%s" -> "%s";' % (self.source, self.target)

    def __eq__(self, other):
        return isinstance(other, Arc) and (self.target == other.target) and (self.source == other.source)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return self.source.__hash__()


class Subnet(dict):

    def __init__(self, source):
        self.update(source)

    def __key(self):
        return self['SubnetId']

    def __hash__(self):
        return hash(self.__key())

    def __eq__(self, other):
        return self.__key() == other.__key()

    def __str__(self):
        return str(self.__key())


class Vpc(dict):

    def __init__(self, source):
        self.update(source)

    def __key(self):
        return self['VpcId']

    def __hash__(self):
        return hash(self.__key())

    def __eq__(self, other):
        return self.__key() == other.__key()

    def __str__(self):
        return str(self.__key())


class IpPermissions(dict):

    def __init__(self, source):
        self.update(source)

    def __key(self):
        return str(tuple((k, self[k]) for k in sorted(self)))

    def __hash__(self):
        return hash(self.__key())

    def __eq__(self, other):
        return self.__key() == other.__key()

    def __str__(self):
        return str(self.__key())


class EC2Instance(dict):

    def __init__(self, source):
        self.update(source)

    def __key(self):
        return self['InstanceId']

    def __hash__(self):
        return hash(self.__key())

    def __eq__(self, other):
        return self.__key() == other.__key()

    def __str__(self):
      return self.__key()


class SecurityGroup(dict):

    def __init__(self, source):
        self.update(source)

    def __key(self):
        return self['GroupId']

    def __hash__(self):
        return hash(self.__key())

    def __eq__(self, other):
        return self.__key() == other.__key()

    def __str__(self):
        return self.__key()


class LoadBalancer(dict):

    def __init__(self, source):
        self.update(source)

    def __key(self):
        return self['LoadBalancerName']

    def __hash__(self):
        return hash(self.__key())

    def __eq__(self, other):
        return self.__key() == other.__key()

    def __str__(self):
        return self.__key()

    def get_vpc_id(self):
        return self['VpcId'] if 'VpcId' in self else self['VPCId']

    def get_subnets(self):
        return self['Subnets'] if 'Subnets' in self else list(map(lambda a: a['SubnetId'], self['AvailabilityZones']))


class AWSVisualizer:

    def __init__(self):
        self.use_security_group_subgraphs = False
        self.use_subnets = False
        self.directory = '.'
        self.vpcs = None
        self.instances = None
        self.security_groups = None
        self.region = None
        self.profile = None
        self.EC2 = None
        self.ELB = None
        self.subnets = {}
        self.assigned_security_groups = {}
        self.loadbalancers = None
        self.ips = {}
        self.exclude_security_groups = set()
        self.ArnToAssume = None

    def connect(self):

        kwargs = {}
        if self.profile:
            kwargs['profile_name'] = self.profile
        if self.region:
            kwargs['region_name'] = self.region
        session = boto3.Session(**kwargs)
        if self.ArnToAssume:
            sts = session.client('sts')
            assumedSession = sts.assume_role(RoleArn=self.ArnToAssume, RoleSessionName='aws-visualizer-session')
            kwargs['aws_access_key_id'] = assumedSession['Credentials']['AccessKeyId']
            kwargs['aws_secret_access_key'] = assumedSession['Credentials']['SecretAccessKey']
            kwargs['aws_session_token'] = assumedSession['Credentials']['SessionToken']
            session = boto3.Session(**kwargs)
        self.EC2 = session.client('ec2')
        self.ELB = session.client('elb')
        self.ELBv2 = session.client('elbv2')
        self.region = session.region_name
        self.load()

    def load(self):
        self.vpcs = list(map(lambda v: Vpc(v), self.EC2.describe_vpcs()['Vpcs']))
        self.loadbalancers = list(map(lambda lb: LoadBalancer(
            lb), self.ELB.describe_load_balancers()['LoadBalancerDescriptions']))
        self.loadbalancers.extend(list(map(lambda lb: LoadBalancer(
            lb), self.ELBv2.describe_load_balancers()['LoadBalancers'])))
        self.security_groups = list(map(lambda g: SecurityGroup(
            g), self.EC2.describe_security_groups()['SecurityGroups']))

        self.instances = []
        self.reservations = self.EC2.describe_instances()['Reservations']
        for r in self.reservations:
            for i in r['Instances']:
                if i['State']['Name'] != "terminated":
                    self.instances.append(EC2Instance(i))

        self.load_all_ips()
        self.load_subnets()
        self.load_assigned_security_groups()
        self.load_assigned_lb_security_groups()

    def get_security_group_by_id(self, id):
        for group in self.security_groups:
            if id == group['GroupId']:
                return group
        assert False, "No security group with id %s was found." % id

    def get_instance_by_id(self, id):
        for instance in self.instances:
            if id == instance['InstanceId']:
                return instance
        assert False, "No instance with id %s was found." % id

    def load_all_ips(self):
        for vpc in self.vpcs:
            self.ips[vpc['VpcId']] = set()
        for vpc in self.vpcs:
            for instance in self.get_instances_in_vpc(vpc['VpcId']):
                if 'PublicIpAddress' in instance:
                    self.ips[vpc['VpcId']].update(
                        [instance['PublicIpAddress']])
                if 'PrivateIpAddress' in instance:
                    self.ips[vpc['VpcId']].update(
                        [instance['PrivateIpAddress']])
            self.ips[vpc['VpcId']] = list(map(lambda ip: IPAddress(ip), filter(
                lambda ip: ip != None, self.ips[vpc['VpcId']])))

    def load_subnets(self):
        self.subnets = {}
        for vpc in self.vpcs:
            self.subnets[vpc['VpcId']] = list(map(lambda s: Subnet(s), self.EC2.describe_subnets(
                Filters=[{'Name': 'vpc-id', 'Values': [vpc['VpcId']]}])['Subnets']))

    def load_assigned_security_groups(self):
        self.assigned_security_groups = {}
        for instance in self.instances:
            self.assigned_security_groups[instance] = list(map(
                lambda g: SecurityGroup(g), instance['SecurityGroups']))

    def load_assigned_lb_security_groups(self):
        self.assigned_lb_security_groups = {}
        for lb in self.loadbalancers:
            self.assigned_lb_security_groups[lb] = list(map(
                lambda g: self.get_security_group_by_id(g), lb['SecurityGroups']))

    def get_networks_of_rule_refering_to_external_address(self, vpc, rule):
        cidrs = rule['IpRanges'] if 'IpRanges' in rule else set()
        networks = set(map(lambda cidr: IPNetwork(cidr), cidrs))
        return list(filter(lambda network: not network.is_private(), networks))

    def get_networks_refering_to_external_address(self, vpc, security_group):
        result = []
        for rule in list(map(lambda r: IpPermissions(r), security_group['IpPermissions'])):
            result += self.get_networks_of_rule_refering_to_external_address(
                vpc, rule)
        return result

    def rule_refers_to_external_address(self, vpc, rule):
        return len(self.get_networks_of_rule_refering_to_external_address(vpc, rule)) != 0

    def find_all_groups_refering_outside_ip_address_in_vpc(self, vpc):
        result = {}
        for security_group in self.security_groups:
            networks = self.get_networks_refering_to_external_address(
                vpc, security_group)
            if len(networks) != 0:
                result[security_group] = networks
        return result

    def is_grantee_of_security_rule(self, rule, instance):
        result = False
        for grant in rule.grants:
            if grant.group_id in self.assigned_security_groups[instance]:
                result = True
            if grant.cidr_ip != None:
                network = IPNetwork(grant.cidr_ip)
                if instance.private_ip_address != None and IPAddress(instance.private_ip_address) in network:
                    result = True
                if instance.ip_address != None and IPAddress(instance.ip_address) in network:
                    result = True
        return result

    def is_grantee_of_security_group(self, security_group, instance):
        result = False
        for rule in list(map(lambda r: IpPermissions(r), security_group['IpPermissions'])):
            if self.is_grantee_of_security_rule(rule, instance):
                result = True
        return result

    def find_grantees_of_security_group(self, security_group):
        return set(filter(lambda instance: self.is_grantee_of_security_group(security_group, instance), self.instances))

    def find_instances_in_network_in_vpc(self, vpc, network):
        return set(
            filter(lambda instance: security_group.id in self.assigned_security_groups[instance], self.instances))

    def find_instances_with_assigned_security_group(self, security_group_id):
        return set(
            filter(lambda instance: security_group_id in self.assigned_security_groups[instance], self.instances))

    def find_loadbalancers_with_assigned_security_group(self, security_group_id):
        return list(filter(lambda lb: security_group_id in self.assigned_lb_security_groups[lb], self.loadbalancers))

    def instance_in_network(self, instance, network):
        return instance.private_ip_address != None and IPAddress(instance.private_ip_address) in network or \
               instance.ip_address != None and IPAddress(
            instance.ip_address) in network

    def find_instances_in_network(self, network):
        return set(filter(lambda instance: self.instance_in_network(instance, network), self.instances_in_current_vpc))

    def _add_rule_to_security_table(self, source, target, rule):
        if source != target:
            if target not in self.security_table[source]:
                self.security_table[source][target] = set()
            self.all_sources.update([source])
            self.all_targets.update([target])
            self.security_table[source][target].update([rule])

    def _add_security_group_to_table(self, target, group):
        if group['GroupId'] in self.exclude_security_groups:
            return

        for rule in list(map(lambda r: IpPermissions(r), group['IpPermissions'])):
            if 'IpRanges' in rule:
                for cidr in rule['IpRanges']:
                    network = IPNetwork(cidr['CidrIp'])
                    self._add_rule_to_security_table(network, target, rule)

            if 'UserIdGroupPairs' in rule:
                for group_pairs in rule['UserIdGroupPairs']:
                    granted_group_id = self.get_security_group_by_id(group_pairs[
                                                                         'GroupId'])
                    sources = self.find_instances_with_assigned_security_group(
                        granted_group_id)
                    for source in sources:
                        self._add_rule_to_security_table(source, target, rule)

                    loadbalancers = self.find_loadbalancers_with_assigned_security_group(
                        granted_group_id)
                    for loadbalancer in loadbalancers:
                        self._add_rule_to_security_table(
                            loadbalancer, target, rule)

    def load_security_table_of_vpc(self, vpc_id):
        self.all_sources = set()
        self.all_targets = set()
        self.security_table = defaultdict(dict)
        self.instances_in_current_vpc = self.get_instances_in_vpc(vpc_id)
        for instance in self.instances_in_current_vpc:
            for sg in instance['SecurityGroups']:
                group = self.get_security_group_by_id(sg['GroupId'])
                self._add_security_group_to_table(instance, group)

        for loadbalancer in self.get_loadbalancers_in_vpc(vpc_id):
            for sg in loadbalancer['SecurityGroups']:
                group = self.get_security_group_by_id(sg)
                self._add_security_group_to_table(loadbalancer, group)

    def rule_as_string(self, rule):
        protocol = rule['IpProtocol'] if rule['IpProtocol'] != "-1" else "all"
        from_port = str(rule['FromPort']) if 'FromPort' in rule and rule[
            'FromPort'] != "-1" else "any"
        to_port = str(rule['ToPort']) if 'ToPort' in rule and rule[
            'ToPort'] != "-1" else "any"

        if from_port == to_port:
            range = from_port
        else:
            range = "%s-%s" % (from_port, to_port)

        if protocol == "tcp":
            result = range
        elif protocol == "icmp":
            result = "icmp"
        else:
            result = "%s(%s)" % (protocol, range)

        if protocol == "all" and from_port == "any" and to_port == "any":
            result = "any"

        return result

    def get_name(self, obj):
        if isinstance(obj, dict) and 'Name' in obj:
            return obj['Name']

        if isinstance(obj, dict) and 'Tags' in obj:
            name_tags = list(filter(lambda t: t['Key'] == 'Name', obj['Tags']))
            if len(name_tags) > 0:
                return name_tags[0]['Value']

        if hasattr(obj, 'id'):
            return obj.id

        return str(obj)

    def print_security_group_table(self, vpc, file):
        file.write(
            '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">\n')
        file.write('<html><head>\n')
        file.write('<title>Security group overview of %s</title>\n' % vpc)
        file.write('</head><body>\n')
        file.write(
            '<table title="security group relations in vpc %s" border="1"><tr><td></td>' % vpc)
        for target in self.all_targets:
            file.write('<td>%s</td>' % self.get_name(target))
        file.write('</tr>\n')
        for source in self.all_sources:
            file.write('<tr><td>%s</td>' % self.get_name(source))
            for target in self.all_targets:
                if target in self.security_table[source]:
                    file.write('<td>%s</td>' % ",".join(list(map(lambda permission: self.rule_as_string(
                        permission), self.security_table[source][target]))))
                else:
                    file.write('<td>%s</td>' % '&nbsp;')
            file.write('</tr>\n')
        file.write('</table><ul>')
        for instance in self.instances_in_current_vpc:
            ip = ' %s' % (instance['PublicIpAddress']
                          if 'PublicIpAddress' in instance else "")
            file.write(
                '<li><a href="https://%s.console.aws.amazon.com/ec2/v2/home?region=%s#Instances:search=%s">%s%s</a> - %s</li>\n' %
                (self.region, self.region, instance['InstanceId'], self.get_name(instance), ip, 'instance'))
        for lb in self.get_loadbalancers_in_vpc(str(vpc)):
            file.write(
                '<li><a href="https://%s.console.aws.amazon.com/ec2/v2/home?region=%s#LoadBalancers:search=%s">%s</a> - %s</li>\n' %
                (self.region, self.region, lb['LoadBalancerName'], self.get_name(lb), 'Elastic Load Balancer'))
        file.write('</ul></body></html>')

    def print_security_group_partition_dot(self, vpc, file):
        partition = defaultdict()
        for instance in self.instances_in_current_vpc:
            key = ",".join(
                list(map(lambda group: group['GroupId'], instance['SecurityGroups'])))
            if not key in partition:
                partition[key] = set()
            partition[key].update([instance])

        count = 0
        for group in partition:
            count += 1
            file.write('subgraph "cluster-%d" {\n' % (count))
            file.write('label = "%s";\n' % group)
            for instance in partition[group]:
                file.write('"%s" [label="%s"];\n' %
                           (instance, self.get_name(instance)))
            file.write('}\n')

    def print_security_group_subnets_dot(self, vpc, file):
        for subnet in self.subnets[vpc['VpcId']]:
            subnet_instances = self.get_instances_in_subnet(subnet['SubnetId'])
            loadbalancers = self.get_loadbalancers_in_subnet(subnet[
                                                                 'SubnetId'])
            # TODO, Loadbalancers may be placed in multiple subnets
            if len(subnet_instances) or len(loadbalancers):
                if self.use_subnets:
                    name = self.get_name(subnet)
                    file.write(
                        'subgraph "cluster-%s" {\n' % (subnet['SubnetId']))
                    file.write('label = "%s";\n' % name)
                for instance in subnet_instances:
                    name = self.get_name(instance)
                    ip = instance[
                        'PublicIpAddress'] if 'PublicIpAddress' in instance else ""
                    file.write('"%s" [label="%s\\n%s"];\n' %
                               (instance, name, ip))
                if self.use_subnets:
                    file.write('}\n')

    def print_security_group_table_dot(self, vpc, file):
        file.write('digraph vpc {\n')
        name = self.get_name(vpc)
        file.write('label = "%s - %s";\n' % (name, vpc['CidrBlock']))

        if self.use_subnets:
            self.print_security_group_subnets_dot(vpc, file)
        elif self.use_security_group_subgraphs:
            self.print_security_group_partition_dot(vpc, file)
        else:
            for node in self.all_sources.union(self.all_targets):
                file.write('"%s" [label="%s"];\n' %
                           (node, self.get_name(node)))

        for source in self.all_sources:
            for target in self.all_targets:
                if target in self.security_table[source]:
                    file.write('"%s" -> "%s";\n' % (source, target))

        file.write('}\n')

    def print_security_group_tables(self):
        for vpc in self.vpcs:
            self.load_security_table_of_vpc(vpc['VpcId'])
            file = open("%s/%s-security-groups.html" %
                        (self.directory, vpc['VpcId']), 'w')
            self.print_security_group_table(vpc, file)
            file.close()

            file = open("%s/%s-security-groups.dot" %
                        (self.directory, vpc['VpcId']), 'w')
            self.print_security_group_table_dot(vpc, file)
            file.close()

    def get_instances_in_vpc(self, vpc_id):
        return list(filter(lambda instance: 'VpcId' in instance and instance['VpcId'] == vpc_id, self.instances))

    def get_loadbalancers_in_vpc(self, vpc_id):
        return list(filter(lambda lb: (lb.get_vpc_id() == vpc_id), self.loadbalancers))

    def get_instances_in_subnet(self, subnet_id):
        return list(filter(lambda instance: 'SubnetId' in instance and instance['SubnetId'] == subnet_id, self.instances))

    def get_loadbalancers_in_subnet(self, subnet_id):
        return list(filter(lambda lb: subnet_id in lb.get_subnets(), self.loadbalancers))


def main():
    parser = argparse.ArgumentParser(description='visualizes the network of security group dependencies in an AWS VPC.')
    parser.add_argument("--directory", "-d", dest="directory", default=".",
                        help="output directory defaults to .", metavar="DIRECTORY")
    parser.add_argument("--use-subnets", "-n",
                        action="store_true", dest="use_subnets", default=False,
                        help="use subnet subgraphs")
    parser.add_argument("--use-security-group-subgraphs", "-s",
                        action="store_true", dest="use_security_group_subgraphs", default=False,
                        help="use security group subgraphs")
    parser.add_argument("--exclude-security-group", "-x",
                        action="append", dest="exclude_security_groups", metavar="SECURITY-GROUP",
                        help="exclude security group")
    parser.add_argument("--profile", "-p", dest="profile",
                        help="select the AWS profile to use")
    parser.add_argument("--region", "-r",
                        dest="region", default="eu-central-1",
                        help="select region to graph")
    parser.add_argument("--assume-role", "-a",
                        dest="ArnToAssume", default="", metavar="ROLE",
                        help="ARN of the role to assume")

    options = parser.parse_args()
    visualizer = AWSVisualizer()
    visualizer.use_security_group_subgraphs = options.use_security_group_subgraphs
    visualizer.use_subnets = options.use_subnets
    visualizer.directory = options.directory
    if options.exclude_security_groups:
        visualizer.exclude_security_groups = options.exclude_security_groups
    visualizer.region = options.region
    if options.profile:
        visualizer.profile = options.profile
    if options.ArnToAssume:
        visualizer.ArnToAssume = options.ArnToAssume
    visualizer.connect()
    visualizer.print_security_group_tables()

if __name__ == '__main__':
    main()
