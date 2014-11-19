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

	def connect(self):
		self.EC2 = boto.ec2.connect_to_region(self.region)
		self.VPC = boto.vpc.connect_to_region(self.region)
		self.ELB = boto.ec2.elb.connect_to_region(self.region)

	def load(self):
		self.security_groups = self.EC2.get_all_security_groups()
		self.instances = self.EC2.get_only_instances(max_results=200)
		self.vpcs = self.VPC.get_all_vpcs()
		self.load_subnets()
		self.load_assigned_security_groups()
		self.loadbalancers = self.ELB.get_all_load_balancers()

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
			 	if IPAddress(instance.private_ip_address) in network:
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
				lb_instances = self.get_loadbalancers_in_subnet(subnet.id)
				if len(subnet_instances) or len(lb_instances):
					if self.use_subgraphs:
						name = subnet.tags['Name'] if 'Name' in subnet.tags else subnet.id
						self.output.write('subgraph "cluster-%s\n" {' % (subnet.id))
					self.output.write('label = "%s";\n' % name)
					for instance in  subnet_instances:
						name = instance.tags['Name'] if 'Name' in instance.tags else instance.id
						self.output.write('"%s" [label="%s"];\n' % (instance.id, name))
					if self.use_subgraphs:
						self.output.write('}\n')
			self.print_security_group_relations(vpc.id)
			self.output.write('}\n')
			self.output.close()

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

(options, args) = parser.parse_args()
visualizer = AWSVisualizer()
visualizer.use_subgraphs = options.use_subgraphs
visualizer.directory = options.directory
visualizer.connect()
visualizer.load()
visualizer.print_dot()
