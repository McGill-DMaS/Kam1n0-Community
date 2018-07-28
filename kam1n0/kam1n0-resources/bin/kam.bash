#!/bin/bash
# ***************************************************************************
# Copyright 2015 McGill University. All rights reserved.                       
#                                                                               
# Unless required by applicable law or agreed to in writing, the software      
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF      
# ANY KIND, either express or implied.                                         
# ***************************************************************************
SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
file = "${SCRIPTPATH}/kam1n0.properties"
unset opts
while IFS='=' read -r key value
do
	 if [[ ${key} == "jvm-option" ]]; then export opts="${opts} ${value}"
done
export EDIR="${SCRIPTPATH}/kam1n0-server.jar%"
echo java ${opts} -jar ${EDIR} "$@" 
java ${opts} -jar ${EDIR} "$@"

