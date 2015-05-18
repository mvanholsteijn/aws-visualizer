from optparse import OptionParser, Option
import boto.ec2
import re
import sys
import readline


class InstanceStopper:
	def __init__(self):
		self.instances = None
		self.region = 'eu-west-1'
		self.EC2 = None
		self.dry_run = False
		self.force = False

	def connect(self):
		self.EC2 = boto.ec2.connect_to_region(self.region)
		self.load()

	def load(self):
		self.instances = self.EC2.get_only_instances(max_results=200)

	def stop_all_instances(self):
		to_stop = []
		for instance in self.instances:
			if instance.state == "running":
				tags = self.EC2.get_all_tags(filters={'resource-id' : instance.id, 
										'tag-value' : 'stopkillingme'})
				if len(tags) == 0 :
					to_stop.append(instance)

		if len(to_stop) > 0: 
			print 'INFO: stopping %d instances.' % len(to_stop)
			if self.force or self.dry_run:
				answer = "yes"
			else:
				answer = raw_input("Are you sure you want to continue? ") 

			if answer == "yes":
				for instance in to_stop:
					print 'INFO: stopping instance %s' % instance.id
					if not self.dry_run:
						self.EC2.stop_instances(instance_ids=[instance.id])
			else:
				print "ERROR: Aborted."

		else:
			print 'INFO: no instances to stop.' 


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
parser.add_option("-r", "--region",
                  dest="region", default="eu-west-1",
                  help="select region to stop instances in")
parser.add_option("-f", "--force",
                  dest="force", default=False, action="store_true",
                  help="Force stop without questions")
parser.add_option("-d", "--dry-run",
                  dest="dry_run", default=False, action="store_true",
                  help="do a dry run")


(options, args) = parser.parse_args()
stopper = InstanceStopper()
stopper.region = options.region
stopper.dry_run = options.dry_run
stopper.force = options.force

stopper.connect()
stopper.stop_all_instances()
