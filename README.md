aws-visualizer
==============
Visualizing an AWS region.

Generates a DOT file, for each VPC in the region.
Generates a security group HTML table showing all grants, for each VPC in the region.

graph_region.py [--directory output-directory ] 
	[ --use-subnets | --use-security-group-subgraphs ] 
	[--region aws-region] 
	[--exclude-security-group security-group]
	[--no-dot-output]

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
- pip install boto netaddr

Quickstart
-----------
./run.sh will generate three different views for each subnet in target: default, securitygroups and subnet.
