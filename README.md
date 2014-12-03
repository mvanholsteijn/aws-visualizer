aws-visualizer
==============
Visualizing an AWS region.

Generates a DOT file, for each VPC in the region.

graph_region.py [--directory output-directory ] [ --show-external-only ] [ --use-subgraphs ] [--region aws-region] [--exclude-security-group security-group]

--show-external-only
	only the external network connections are revealed and network addresses are shown.
	default is false.

--use-subgraphs
	uses subgraphs for use subnet in the vpc.
	default is false.

--exclude-security-group
	comma separated list of security groups to exclude from graph. 

INSTALL
-------
- install python
- install graphviz
- pip install boto netaddr

Quickstart
-----------
./run.sh will generate three different views for each subnet in target: default, external and subnet.
