A visualizer of the network of security group dependencies in an AWS VPC.

Based on the dependencies of the security groups within a VPC, it can generate the following:

- An HTML table with all security group dependencies between network components.
- A dot graph of all security group dependencies between network components.
- A dot graph of all security group dependencies between network components grouped by security groups.
- A dot graph of all security group dependencies between network components grouped by subnet.

**Usage**

aws-visualizer [-h] [--directory DIRECTORY] [--use-subnets]
                       [--use-security-group-subgraphs]
                       [--exclude-security-group SECURITY-GROUP]
                       [--profile PROFILE] [--region REGION]
                       [--assume-role ROLE]


optional arguments::
  -h, --help            show this help message and exit
  --directory DIRECTORY, -d DIRECTORY
                        output directory defaults to .
  --use-subnets, -n     use subnet subgraphs
  --use-security-group-subgraphs, -s
                        use security group subgraphs
  --exclude-security-group SECURITY-GROUP, -x SECURITY-GROUP
                        exclude security group
  --profile PROFILE, -p PROFILE
                        select the AWS profile to use
  --region REGION, -r REGION
                        select region to graph
  --assume-role ROLE, -a ROLE
                        ARN of the role to assume

**Example**

To generate the default graph, type::

	$ aws-visualizer --directory /tmp/aws-visualizer
	$ for F in /tmp/aws-visualizer/*.dot; do dot -Tpng -o $(dirname $F)/$(basename $F .dot).png  $F; done
	$ open /tmp/aws-visualizer/*.png

**Installation**

To install, type::
	pip install aws-visualizer
