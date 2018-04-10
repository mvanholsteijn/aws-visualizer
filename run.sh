#!/bin/bash
#   Copyright 2015 Xebia Nederland B.V.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

function check_pip_installed() {
	PIP=$(which pip)
	if [ -z "$PIP" ] ; then
		echo ERROR: Python not installed
		exit 1
	fi
	for module in $@ ; do
		INSTALLED=$(pip show $module 2>/dev/null)
		if [ -z "$INSTALLED" ] ; then
			echo ERROR: module $module not installed. 	
			echo ERROR: please run pip install $@
			exit 1
		fi
	done
}

check_pip_installed boto3 netaddr

if [ ! -f ~/.aws/credentials ] ; then
	echo ERROR: ~/.aws/credentials are missing. 
	echo '	[default]'
	echo '	aws_access_key_id = <ACCESS_KEY>'
	echo '	aws_secret_access_key = <SECRET_KEY>'
	exit 1
fi

rm -rf target
mkdir -p target/default
mkdir -p target/securitygroups
mkdir -p target/subnets

echo INFO: graphing default dependencies
python graph_region.py  --directory target/default $@
echo INFO: graphing with subnets
python graph_region.py  --directory target/subnets --use-subnets $@
echo INFO: graphing with security groups 
python graph_region.py  --directory target/securitygroups --use-security-group-subgraphs $@


DOT=$(which dot)
if [ -n "$DOT" ] ; then
	for file in target/*/*.dot; do
		echo INFO: generating png for $file
		dot -Tpng -o $(dirname $file)/$(basename $file .dot).png  $file
	done
	if [ "$(uname)" == "Darwin" ] ; then
		open target/*/*.png
	else
		echo INFO: Done. checkout target/ subdirectories
	fi
else
	echo WARN: dot not installed.
fi
