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

read -e -p 'AWS Profile [default]:' profilename
profilename=${profilename:-default}
read -e -p 'AWS Region [eu-central-1]:' profileregion
profileregion=${profileregion:-eu-central-1}

rm -rf target/$profilename
mkdir -p target/$profilename/default
mkdir -p target/$profilename/securitygroups
mkdir -p target/$profilename/subnets

echo INFO: graphing default dependencies
aws-visualizer -p $profilename --directory target/$profilename/default -r $profileregion $@
echo INFO: graphing with subnets
aws-visualizer -p $profilename --directory target/$profilename/subnets -r $profileregion --use-subnets $@
echo INFO: graphing with security groups 
aws-visualizer -p $profilename --directory target/$profilename/securitygroups -r $profileregion --use-security-group-subgraphs $@


DOT=$(which dot)
DOTFILE=$(find target/$profilename -type f -name '*.dot')

if [ -n "$DOT" ] ; then
	for file in $DOTFILE; do
		echo INFO: generating png for $file
		dot -Tpng -o $(dirname $file)/$(basename $file .dot).png  $file
	done
	if [ "$(uname)" == "Darwin" ] ; then
		open $(sed -e 's/\.dot/\.png/g' <<< $DOTFILE)
	else
		echo INFO: Done. checkout target/ subdirectories
	fi
else
	echo WARN: dot not installed.
fi
