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
		self.use_security_group_subgraphs = False
		self.use_subnets = False
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
		self.load_assigned_lb_security_groups()

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
			self.assigned_security_groups[instance] = set(map(lambda group : group.id, instance.groups))

	def load_assigned_lb_security_groups(self):
		self.assigned_lb_security_groups = {}
		for lb in self.loadbalancers:
			self.assigned_lb_security_groups[lb] = set(lb.security_groups)

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
		for rule in security_group.rules:
			if self.is_grantee_of_security_rule(rule, instance):
				result = True
		return result

	def find_grantees_of_security_group(self,security_group):
		return set(filter(lambda instance : self.is_grantee_of_security_group(security_group, instance), self.instances))

	def find_instances_in_network_in_vpc(self,vpc, network):
		return set(filter(lambda instance : security_group.id in self.assigned_security_groups[instance], self.instances))

	def find_instances_with_assigned_security_group(self,security_group):
		return set(filter(lambda instance : security_group.id in self.assigned_security_groups[instance], self.instances))

	def find_loadbalancers_with_assigned_security_group(self,security_group):
		return set(filter(lambda lb : security_group.id in self.assigned_lb_security_groups[lb], self.loadbalancers))

	def  instance_in_network(self,instance, network):
		return instance.private_ip_address != None and IPAddress(instance.private_ip_address) in network or \
		       instance.ip_address != None and IPAddress(instance.ip_address) in network

	def find_instances_in_network(self, network):
		return set (filter(lambda instance : self.instance_in_network(instance, network) , self.instances_in_current_vpc))

	def _add_rule_to_security_table(self, source, target, rule):
		if source != target:
			if target not in self.security_table[source]:
				self.security_table[source][target] = set()
			self.security_table[source][target].update([rule])
			self.all_sources.update([source])
			self.all_targets.update([target])

	def _add_security_group_to_table(self, target, group):
		for rule in group.rules:
			for grant in rule.grants:
				if grant.cidr_ip != None:
					network = IPNetwork(grant.cidr_ip)
					self._add_rule_to_security_table(network, target, rule)

				if grant.group_id != None:
					granted_group = self.get_security_group_by_id(grant.group_id)

					sources = self.find_instances_with_assigned_security_group(granted_group)
					for source in sources:
						self._add_rule_to_security_table(source, target, rule)

					loadbalancers = self.find_loadbalancers_with_assigned_security_group(granted_group)
					for loadbalancer in loadbalancers:
						self._add_rule_to_security_table(loadbalancer, target, rule)

	def load_security_table_of_vpc(self,vpc_id):
		self.all_sources = set()
		self.all_targets = set()
		self.security_table = defaultdict(dict)
		self.instances_in_current_vpc = self.get_instances_in_vpc(vpc_id)
		for instance in self.instances_in_current_vpc:
			for sg in instance.groups:
				group = self.get_security_group_by_id(sg.id)
				self._add_security_group_to_table(instance, group)

		for loadbalancer in self.get_loadbalancers_in_vpc(vpc_id):
			for sg in loadbalancer.security_groups:
				group = self.get_security_group_by_id(sg)
				self._add_security_group_to_table(loadbalancer, group)

	def rule_as_string(self, rule):
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

	def get_name(self,object):
		if hasattr(object, 'name'):
			name = object.name
		elif hasattr(object, 'tags') and 'Name' in object.tags:
			name = object.tags['Name'] 
		elif hasattr(object, 'id'):
			name = object.id
		else:
			name = str(object)
		return name

	def print_security_group_table(self, vpc, file):
		file.write ('<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">\n')
		file.write ('<html><head>\n')
		file.write ('<title>Security group overview of %s</title>\n' % vpc)
		file.write ('</head><body>\n')
		file.write('<table title="security group relations in vpc %s" border="1"><tr><td></td>' % vpc)
		for target in self.all_targets:
			file.write('<td>%s</td>' % self.get_name(target))
		file.write('</tr>\n')
		for source in self.all_sources:
			file.write('<tr><td>%s</td>' % self.get_name(source))
			for target in self.all_targets:
				if target in self.security_table[source]:
					file.write('<td>%s</td>' % ",".join(map(lambda permission : self.rule_as_string(permission), self.security_table[source][target])))
				else:
					file.write('<td>%s</td>' % '&nbsp;')
			file.write('</tr>\n')
		file.write('</table></body></html>')

	def print_security_group_partition_dot(self, vpc, file):
			partition = defaultdict()
			for instance in self.instances_in_current_vpc:
				key = ",".join(map(lambda group : group.id, instance.groups))
				if not key in partition:
					partition[key] = set()
				partition[key].update([instance])

			count=0
			for group in partition:
				count += 1
				file.write('subgraph "cluster-%d" {\n' % (count))
				file.write('label = "%s";\n' % group)
				for instance in partition[group]:
					file.write('"%s" [label="%s"];\n' % (instance, self.get_name(instance)))
				file.write('}\n');

	def print_security_group_subnets_dot(self, vpc, file):
		for subnet in self.subnets[vpc.id]:
			subnet_instances = self.get_instances_in_subnet(subnet.id)
			loadbalancers = self.get_loadbalancers_in_subnet(subnet.id)
			# TODO, Loadbalancers may be placed in multiple subnets 
			if len(subnet_instances) or len(loadbalancers):
				if self.use_subnets:
					name = subnet.tags['Name'] if 'Name' in subnet.tags else subnet.id
					file.write('subgraph "cluster-%s" {\n' % (subnet.id))
					file.write('label = "%s";\n' % name)
				for instance in subnet_instances:
					name = instance.tags['Name'] if 'Name' in instance.tags else instance.id
					ip = instance.ip_address if instance.ip_address else ""
					file.write('"%s" [label="%s\\n%s"];\n' % (instance, name, ip))
				if self.use_subnets:
					file.write('}\n')
			
	def print_security_group_table_dot(self, vpc, file):
		file.write('digraph vpc {\n')
		name = vpc.tags['Name'] if 'Name' in vpc.tags else vpc.id
		file.write('label = "%s - %s";\n' % (name, vpc.cidr_block))

		
		if self.use_subnets:
			self.print_security_group_subnets_dot(vpc, file)
		elif self.use_security_group_subgraphs:
			self.print_security_group_partition_dot(vpc, file)
                else:
			for node in self.all_sources.union(self.all_targets):
				file.write('"%s" [label="%s"];\n' % (node, self.get_name(node)))

		for source in self.all_sources:
			for target in self.all_targets:
				if target in self.security_table[source]:
					file.write('"%s" -> "%s";\n' % (source, target))

	

		file.write('}\n')
		
				
	def print_security_group_tables(self):
		for vpc in self.vpcs:
			self.load_security_table_of_vpc(vpc.id)
			file =  open("%s/%s-security-groups.html" % (self.directory, vpc.id), 'w')
			self.print_security_group_table(vpc, file)
			file.close()

			file =  open("%s/%s-security-groups.dot" % (self.directory, vpc.id), 'w')
			self.print_security_group_table_dot(vpc, file)
			file.close()

	def get_instances_in_vpc(self, vpc_id):
		return filter(lambda instance : instance.vpc_id == vpc_id, self.instances)

	def get_loadbalancers_in_vpc(self, vpc_id):
		return filter(lambda lb : lb.vpc_id == vpc_id, self.loadbalancers)

	def get_instances_in_subnet(self, subnet_id):
		return filter(lambda instance : instance.subnet_id == subnet_id, self.instances)

	def get_loadbalancers_in_subnet(self, subnet_id):
		return filter(lambda lb : subnet_id in lb.subnets, self.loadbalancers)


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
parser.add_option("-n", "--use-subnets",
                  action="store_true", dest="use_subnets", default=False,
                  help="use subnet subgraphs")
parser.add_option("-s", "--use-security-group-subgraphs",
                  action="store_true", dest="use_security_group_subgraphs", default=False,
                  help="use security group subgraphs")
parser.add_option("-x", "--exclude-security-group",
                  action="extend", type="string", dest="exclude_security_group", metavar="SECURITY-GROUP",
                  help="exclude security group")
parser.add_option("-r", "--region",
                  dest="region", default="eu-west-1",
                  help="select region to graph")

(options, args) = parser.parse_args()
visualizer = AWSVisualizer()
visualizer.use_security_group_subgraphs = options.use_security_group_subgraphs
visualizer.use_subnets = options.use_subnets
visualizer.directory = options.directory
visualizer.exclude_security_group= options.exclude_security_group
visualizer.region = options.region

visualizer.connect()
visualizer.print_security_group_tables()
