aws-visualizer
==============
Visualizing an AWS region.

Generates a DOT file, for each VPC in the region.
Generates a security group HTML table showing all grants, for each VPC in the region.

graph\_region.py [--directory output-directory ] 
	[ --use-subnets | --use-security-group-subgraphs ] 
	[--profile aws-profile] 
	[--region aws-region] 
	[--exclude-security-group security-group]
	[--no-dot-output]

--profile aws-profile
	to use to connect 

--region aws-region
	to graph vpc's of

--use-subnets
	uses subgraphs for use subnet in the vpc.
	default is false.

----use-security-group-subgraphs
	uses security group grouping as subgraphs.
	default is false.

--exclude-security-group
	comma separated list of security groups to exclude from graph. 

--no-dot-output
	do not generate dot output files. Will only generate a HTML table


INSTALL
-------
- install python
- install graphviz
- pip install boto3 netaddr


Authenticating
--------------
AWS Visualizer uses the `boto3` library to make it's calls to the AWS API.  As
such it supports all of the tratitional boto mechanisms for [specifying
credentials](http://boto3.readthedocs.io/en/latest/guide/configuration.html#guide-configuration)

Given the following `~/.aws/credentials` file:

```
[default]
aws_access_key_id = <your default access key>
aws_secret_access_key = <your default secret key>

[name_goes_here]
aws_access_key_id = <access key for this profile>
aws_secret_access_key = <secret key for this profile>

[another_profile]
aws_access_key_id = <access key for this profile>
aws_secret_access_key = <secret key for this profile>
aws_security_token = <optional security token for this profile>
```

One can differentiate between different profiles by running commands like:

```
python graph_region.py --profile name_goes_here --directory /tmp/ --use-subnets --region us-west-1
profile python graph_region.py --profile another_profile --directory /tmp/ --use-subnets --region us-west-1
```

Conversely, for users who do not have an `~/.aws/credentials` file the options
can be provided as environment variables:

```
AWS_ACCESS_KEY_ID=OXOXOXOXXOXOXO AWS_SECRET_ACCESS_KEY=QWQWQQWQWQWQWQW python graph_region.py --directory /tmp/ --use-subnets --region us-west-1
```

Quickstart
-----------
./run.sh will generate three different views for each subnet in target: default, securitygroups and subnet.
