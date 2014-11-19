import boto.ec2
from boto.vpc import VPCConnection



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
		self.vpcs = None
		self.instances = None
		self.security_groups = None
		self.region = 'eu-west-1'
		self.EC2 = None
		self.VPC = None
		self.subnets = {}
		self.assigned_security_groups = {}

	def connect(self):
		self.EC2 = boto.ec2.connect_to_region('eu-west-1')
		self.VPC = boto.vpc.connect_to_region('eu-west-1')

	def load(self):
		self.security_groups = self.EC2.get_all_security_groups()
		self.instances = self.EC2.get_only_instances(max_results=200)
		self.vpcs = self.VPC.get_all_vpcs()
		self.load_subnets()
		self.load_assigned_security_groups()

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
		
	
	def get_instances_in_subnet(self, subnet_id):
		result = []
		for instance in self.instances:
			if instance.subnet_id == subnet_id:
				result.append(instance)
		return result

	def print_dot(self):
		print "digraph region {"
		for vpc in self.vpcs:
			for subnet in self.subnets[vpc.id]:
				subnet_instances = self.get_instances_in_subnet(subnet.id)
				if len(subnet_instances):
					name = subnet.tags['Name'] if 'Name' in subnet.tags else subnet.id
					print 'subgraph "cluster-%s" {' % (subnet.id)
					print 'label = "%s";' % name;
					for instance in  subnet_instances:
						name = instance.tags['Name'] if 'Name' in instance.tags else instance.id
						print '"%s" [label="%s"];' % (instance.id, name)
					print '}'
		self.print_security_group_relations()
		print '}'

	def print_security_group_relations(self):
		network_connections = set()
		for security_group in self.security_groups:
			grantees = self.find_grantees_of_security_group(security_group)
			grantors = self.find_instances_with_assigned_security_group(security_group)
			for grantee in grantees:
				for grantor in grantors:
					network_connections.update([Arc(grantee, grantor)])

		for arc in network_connections:
			print arc

visualizer = AWSVisualizer()
visualizer.connect()
visualizer.load()
assert 'sg-b02c96d5' in visualizer.assigned_security_groups['i-524d7bb7']
assert 'sg-301ea455' in visualizer.assigned_security_groups['i-524d7bb7']

visualizer.print_dot()
