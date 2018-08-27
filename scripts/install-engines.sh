#!/bin/bash

TRUSTED_HOSTS=""
#TRUSTED_HOSTS="--trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org"

# Check if python2.7 if installed
python_bin=$(which python2.7)
[ ${python_bin} ] || { echo "Installation Error: 'Python2.7' is required and not installed." ; exit -1; }

RED='\033[0;31m'
NC='\033[0m' # No Color

engines_path=$PWD"/../engines" # change the path if needed

for engine_dir in $engines_path/*; do
	echo ${engine_dir}
	if [ -f "${engine_dir}/requirements.txt" ]; then
		cd ${engine_dir}
		rm -rf env
		${python_bin} -m virtualenv env
		. env/bin/activate
		env/bin/pip install -r requirements.txt $TRUSTED_HOSTS
		deactivate
	fi
done

echo -e "${RED}Important Notice:${NC}"
echo "For each engine, please copy the default configuration file and update settings."


exit 0
