import boto.ec2
from boto.vpc import VPCConnection


class AWSVisualizer:

	def __init__(self):
		self.vpcs = None
		self.instances = None
		self.security_groups = None
		self.region = 'eu-west-1'
		self.EC2 = None
		self.VPC = None

	def connect(self):
		self.EC2 = boto.ec2.connect_to_region('eu-west-1')
		self.VPC = boto.vpc.connect_to_region('eu-west-1')

	def load(self):
		self.security_groups = self.EC2.get_all_security_groups()
		self.instances = self.EC2.get_only_instances(max_results=200)
		self.vpcs = self.VPC.get_all_vpcs()
		self.subnets = {}
		for vpc in self.vpcs:
			self.subnets[vpc.id] = self.VPC.get_all_subnets(filters={'vpc-id': vpc.id})

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
					print 'label = "%s;"' % name;
					for instance in  subnet_instances:
						name = instance.tags['Name'] if 'Name' in instance.tags else instance.id
						print '"%s" [label="%s"];' % (instance.id, name)
					print '}'
		print '}'

visualizer = AWSVisualizer()
visualizer.connect()
visualizer.load()
visualizer.print_dot()
