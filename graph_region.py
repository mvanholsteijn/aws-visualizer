from optparse import OptionParser, Option
import boto.ec2
import boto.vpc
import boto.ec2.elb
from netaddr import IPNetwork, IPAddress
import re
from collections import defaultdict
import sys

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

class AWSVisualizer:
	def __init__(self):
		self.show_external_only = False
		self.use_subgraphs = True
		self.directory = '.'
		self.vpcs = None
		self.instances = None
		self.security_groups = None
		self.region = 'eu-west-1'
		self.EC2 = None
		self.VPC = None
		self.ELB = None
		self.subnets = {}
		self.assigned_security_groups = {}
		self.loadbalancers = None
		self.ips = {}
		self.exclude_security_groups = set()

	def connect(self):
		self.EC2 = boto.ec2.connect_to_region(self.region)
		self.VPC = boto.vpc.connect_to_region(self.region)
		self.ELB = boto.ec2.elb.connect_to_region(self.region)
		self.load()

	def load(self):
		self.vpcs = self.VPC.get_all_vpcs()
		self.loadbalancers = self.ELB.get_all_load_balancers()
		self.security_groups = self.EC2.get_all_security_groups()
		self.instances = self.EC2.get_only_instances(max_results=200)

		self.load_all_ips()
		self.load_subnets()
		self.load_assigned_security_groups()

	def get_security_group_by_id(self, id):
		for group in self.security_groups:
			if id == group.id:
				return group
		assert False, "No security group with id %s was found." % id

	def get_instance_by_id(self, id):
		for instance in self.instances:
			if id == instance.id:
				return instance
		assert False, "No instance with id %s was found." % id

	def load_all_ips(self):
		for vpc in self.vpcs:
			self.ips[vpc.id] = set()
		for vpc in self.vpcs:
			for instance in self.get_instances_in_vpc(vpc.id):
				self.ips[vpc.id].update([instance.ip_address, instance.private_ip_address])
			self.ips[vpc.id] = map(lambda ip : IPAddress(ip), filter(lambda ip : ip != None, self.ips[vpc.id]))

	def load_subnets(self):
		self.subnets = {}
		for vpc in self.vpcs:
			self.subnets[vpc.id] = self.VPC.get_all_subnets(filters={'vpc-id': vpc.id})

	def load_assigned_security_groups(self):
		self.assigned_security_groups = {}
		for instance in self.instances:
			groups = set()
			for security_group in instance.groups:
				groups.update([security_group.id])
			self.assigned_security_groups[instance.id] = groups



	def get_networks_of_rule_refering_to_external_address(self, vpc, rule):
		cidrs = set(map(lambda grant : grant.cidr_ip, filter(lambda g : g.cidr_ip != None, rule.grants)))
		networks = set(map(lambda cidr : IPNetwork(cidr), cidrs))
		return filter(lambda network : not network.is_private(), networks)

	def get_networks_refering_to_external_address(self, vpc, security_group):
		result = []
		for rule in security_group.rules:
			result += self.get_networks_of_rule_refering_to_external_address(vpc, rule)
		return result

	def rule_refers_to_external_address(self, vpc, rule):
		return len(self.get_networks_of_rule_refering_to_external_address(vpc, rule)) != 0
		
	def find_all_groups_refering_outside_ip_address_in_vpc(self, vpc):
		result = {}
		for security_group in self.security_groups:
			networks = self.get_networks_refering_to_external_address(vpc, security_group)
			if len(networks) != 0:
				result[security_group] = networks
		return result
		
	def find_all_groups_refering_outside_ip_address(self):
		for vpc in self.vpcs:
			self.find_all_groups_refering_outside_ip_address_in_vpc(vpc.id)
		
	def is_grantee_of_security_rule(self, rule, instance):
		result = False
		for grant in rule.grants:
			if grant.group_id in self.assigned_security_groups[instance.id]:
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
		for rule in security_group.rules:
			if self.is_grantee_of_security_rule(rule, instance):
				result = True
		return result

	def find_grantees_of_security_group(self,security_group):
		result = set()
		for instance in self.instances:
			if self.is_grantee_of_security_group(security_group, instance):
				result.update([instance.id])
		return result

	def find_instances_with_assigned_security_group(self,security_group):
		result = set()
		for instance in self.instances:
			if security_group.id in self.assigned_security_groups[instance.id]:
				result.update([instance.id])
		return result

	def get_instance_name(self, instance):
		return instance.tags['Name'] if 'Name' in instance.tags else instance.id
		
	def rule_key(self, rule):
		protocol = rule.ip_protocol if rule.ip_protocol != "-1" else "all"
		from_port = rule.from_port if rule.from_port and rule.from_port != "-1" else "any"
		to_port = rule.to_port if rule.to_port and rule.from_port != "-1"   else "any"

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

	def get_security_table(self,vpc_id):
		all_sources = set()
		all_targets = set()
		security_table = defaultdict(dict)
		for instance in self.get_instances_in_vpc(vpc_id):
			dest_inst_name = self.get_instance_name(instance)
			for sg in instance.groups:
				group = self.get_security_group_by_id(sg.id)
				for rule in group.rules:
					range = self.rule_key(rule)
					for grant in rule.grants:
						if grant.cidr_ip != None:
							if dest_inst_name not in security_table[grant.cidr_ip]:
								security_table[grant.cidr_ip][dest_inst_name] = set()
							security_table[grant.cidr_ip][dest_inst_name].update([range])
							all_sources.update([grant.cidr_ip])
							all_targets.update([dest_inst_name])
						if grant.group_id != None:
							src_group = self.get_security_group_by_id(grant.group_id)
							for source in self.find_instances_with_assigned_security_group(src_group):
								src_instance = self.get_instance_by_id(source)
								name = self.get_instance_name(src_instance)
								all_sources.update([name])
								if dest_inst_name not in security_table[name]:
									security_table[name][dest_inst_name] = set()
								security_table[name][dest_inst_name].update([range])
								all_targets.update([dest_inst_name])
		return security_table, sorted(all_sources), sorted(all_targets)

	def print_security_group_table_in_vpc(self, vpc_id, file):
		table, sources, targets = self.get_security_table(vpc_id)
		file.write ("""
			<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
			<html>
			<head>
			<title>Security group overview of %s</title>
			</head>
			<body>""" %  vpc_id)
		file.write('<table title="security group relations in vpc %s" border="1"><tr><td></td>' % vpc_id)
		for target in targets:
			file.write('<td>%s</td>' % target)
		file.write('</tr>\n')
		for source in sources:
			file.write('<tr><td>%s</td>' % source)
			for target in targets:
				if target in table[source]:
					file.write('<td>%s</td>' % ",".join(table[source][target]))
				else:
					file.write('<td>%s</td>' % '&nbsp;')
			file.write('</tr>\n')
		file.write('</table></body></html>')

				
	def print_security_group_tables(self):
		for vpc in self.vpcs:
			file =  open("%s/%s-security-groups.html" % (self.directory, vpc.id), 'w')
			self.print_security_group_table_in_vpc(vpc.id, file)
			file.flush()
			file.close()

	def get_instances_in_vpc(self, vpc_id):
		result = []
		for instance in self.instances:
			if instance.vpc_id == vpc_id:
				result.append(instance)
		return result

	def get_instances_in_subnet(self, subnet_id):
		result = []
		for instance in self.instances:
			if instance.subnet_id == subnet_id:
				result.append(instance)
		return result

	def get_loadbalancers_in_subnet(self, subnet_id):
		result = []
		for loadbalancer in self.loadbalancers:
			for subnet in loadbalancer.subnets:
				if subnet == subnet_id:
					result.append(loadbalancer)
		return result
		

	def print_dot(self):
		for vpc in self.vpcs:
			self.output = open("%s/%s.dot" % (self.directory, vpc.id), 'w')
			self.output.write('digraph vpc {\n')
			name = vpc.tags['Name'] if 'Name' in vpc.tags else vpc.id
			self.output.write('label = "%s - %s";\n' % (name, vpc.cidr_block))

			for subnet in self.subnets[vpc.id]:
				subnet_instances = self.get_instances_in_subnet(subnet.id)
				loadbalancers = self.get_loadbalancers_in_subnet(subnet.id)
				if len(subnet_instances) or len(loadbalancers):
					if self.use_subgraphs:
						name = subnet.tags['Name'] if 'Name' in subnet.tags else subnet.id
						self.output.write('subgraph "cluster-%s" {\n' % (subnet.id))
						self.output.write('label = "%s";\n' % name)
					for instance in  subnet_instances:
						name = instance.tags['Name'] if 'Name' in instance.tags else instance.id
						ip = instance.ip_address if instance.ip_address else ""
						self.output.write('"%s" [label="%s\\n%s"];\n' % (instance.id, name, ip))
					if self.use_subgraphs:
						self.output.write('}\n')
			if(not self.show_external_only):
				self.print_security_group_relations(vpc.id)
			self.print_external_networks(vpc.id)
			self.output.write('}\n')
			self.output.close()

	def print_external_networks(self, vpc):
		groups = self.find_all_groups_refering_outside_ip_address_in_vpc(vpc)
		instances_in_vpc = self.get_instances_in_vpc(vpc)
		instance_ids_in_vpc = map(lambda instance: instance.id, instances_in_vpc)
		network_connections = set()
		networks = set()
		if self.use_subgraphs:
			self.output.write('subgraph "cluster-external-%s" {\n' % (vpc))
			self.output.write('label = "external";\n')

		for group in groups:
			grantors = self.find_instances_with_assigned_security_group(group).intersection(instance_ids_in_vpc)
			for grantor in grantors:
				for network in groups[group]:
					networks.update([network])
					source = str(network) if self.show_external_only else "external"
					network_connections.update([Arc(source, grantor)])

		if not self.show_external_only:
			self.output.write('"external" [label="%s"];\n' % ' '.join(str(n) for n in networks))

		for arc in network_connections:
			self.output.write('%s\n' % str(arc)) 

		if self.use_subgraphs:
			self.output.write('}\n')

	def print_security_group_relations(self, vpc):
		network_connections = set()
		instances_in_vpc = map(lambda instance: instance.id, self.get_instances_in_vpc(vpc))
		for security_group in self.security_groups:
			grantees = self.find_grantees_of_security_group(security_group)
			grantors = self.find_instances_with_assigned_security_group(security_group)
			for grantee in grantees.intersection(instances_in_vpc):
				for grantor in grantors.intersection(instances_in_vpc):
					network_connections.update([Arc(grantee, grantor)])

		for arc in network_connections:
			self.output.write('%s\n' % str(arc)) 


class MultipleOption(Option):
    ACTIONS = Option.ACTIONS + ("extend",)
    STORE_ACTIONS = Option.STORE_ACTIONS + ("extend",)
    TYPED_ACTIONS = Option.TYPED_ACTIONS + ("extend",)
    ALWAYS_TYPED_ACTIONS = Option.ALWAYS_TYPED_ACTIONS + ("extend",)

    def take_action(self, action, dest, opt, value, values, parser):
        if action == "extend":
            values.ensure_value(dest, []).append(value)
        else:
            Option.take_action(self, action, dest, opt, value, values, parser)

parser = OptionParser(option_class=MultipleOption)
parser.add_option("-d", "--directory", dest="directory", default=".",
                  help="output directory defaults to .", metavar="DIRECTORY")
parser.add_option("-s", "--use-subgraphs",
                  action="store_true", dest="use_subgraphs", default=False,
                  help="use subnet subgraphs")
parser.add_option("-e", "--show-external-only",
                  action="store_true", dest="show_external_only", default=False,
                  help="only show external network connections")
parser.add_option("-x", "--exclude-security-group",
                  action="extend", type="string", dest="exclude_security_group", metavar="SECURITY-GROUP",
                  help="exclude security group")
parser.add_option("-r", "--region",
                  dest="region", default="eu-west-1",
                  help="select region to graph")

(options, args) = parser.parse_args()
visualizer = AWSVisualizer()
visualizer.use_subgraphs = options.use_subgraphs
visualizer.directory = options.directory
visualizer.show_external_only = options.show_external_only
visualizer.exclude_security_group= options.exclude_security_group
visualizer.region = options.region

visualizer.connect()
visualizer.print_dot()
visualizer.print_security_group_tables()
