from optparse import OptionParser
import boto.ec2
import boto.vpc
import boto.ec2.elb
from netaddr import IPNetwork, IPAddress

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
						self.output.write('"%s" [label="%s"];\n' % (instance.id, name))
					if self.use_subgraphs:
						self.output.write('}\n')
			if(not self.show_external_only):
				self.print_security_group_relations(vpc.id)
			self.print_external_networks(vpc.id)
			self.output.write('}\n')
			self.output.close()

	def print_external_networks(self, vpc):
		groups = self.find_all_groups_refering_outside_ip_address_in_vpc(vpc)
		instances_in_vpc = map(lambda instance: instance.id, self.get_instances_in_vpc(vpc))
		network_connections = set()
		networks = set()
		if self.use_subgraphs:
			self.output.write('subgraph "cluster-external-%s" {\n' % (vpc))
			self.output.write('label = "external";\n')

		for group in groups:
			grantors = self.find_instances_with_assigned_security_group(group).intersection(instances_in_vpc)
			for grantor in grantors:
				for network in groups[group]:
					networks.update([network])
					if self.show_external_only:
						network_connections.update([Arc(str(network), grantor)])
					else:
						network_connections.update([Arc("external", grantor)])
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

parser = OptionParser()
parser.add_option("-d", "--directory", dest="directory", default=".",
                  help="output directory defaults to .", metavar="DIRECTORY")
parser.add_option("-s", "--use-subgraphs",
                  action="store_true", dest="use_subgraphs", default=False,
                  help="use subnet subgraphs")
parser.add_option("-e", "--show-external-only",
                  action="store_true", dest="show_external_only", default=False,
                  help="only show external network connections")
parser.add_option("-r", "--region",
                  dest="region", default="eu-west-1",
                  help="select region to graph")

(options, args) = parser.parse_args()
visualizer = AWSVisualizer()
visualizer.use_subgraphs = options.use_subgraphs
visualizer.directory = options.directory
visualizer.show_external_only = options.show_external_only
visualizer.region = options.region

visualizer.connect()
visualizer.print_dot()
