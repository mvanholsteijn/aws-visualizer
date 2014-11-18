import boto.ec2
from boto.vpc import VPCConnection

EC2 = boto.ec2.connect_to_region('eu-west-1')
VPC = boto.vpc.connect_to_region('eu-west-1')


def get_all_security_groups_in_vpc(vpc):
     result = {}
     all_groups = EC2.get_all_security_groups(filters={'vpc-id': vpc})
     for group in all_groups:
	result[group.id] = group
     return result


def print_sgs(sgs):
    for id in sgs:
	group = sgs[id]
	for rule in group.rules:
		print rule.from_port
		print rule.to_port
		if len(rule.grants):
			for grant in rule.grants:
				print grant.__dict__ 
	
print "digraph region {"
vpcs = VPC.get_all_vpcs()
for vpc in vpcs:
     groups = get_all_security_groups_in_vpc(vpc.id)
     subnets = VPC.get_all_subnets(filters={'vpc-id': vpc.id})
     for subnet in subnets:
	instances = EC2.get_only_instances(filters={'subnet-id': subnet.id}, max_results=200)
	if len(instances):
		name = subnet.tags['Name'] if 'Name' in subnet.tags else subnet.id
		print 'subgraph "cluster-%s" {' % (subnet.id)
		print 'label = "%s;"' % name;
		for instance in  instances:
			name = instance.tags['Name'] if 'Name' in instance.tags else instance.id
			print '"%s" [label="%s"];' % (instance.id, name)
			for group in instance.groups:
				print '//   %s has security group %s ' % (instance.id, group.id)
		print '}'
print '}'
