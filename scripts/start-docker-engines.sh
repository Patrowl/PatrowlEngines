#!/bin/bash

CWD=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
engines_path="$CWD/../engines" # change the path if needed

for engine_dir in $engines_path/*; do
  if [ -f "${engine_dir}/Dockerfile" -a -f "${engine_dir}/${engine_dir##*/}.json" ]; then
    cd $engine_dir
    # get the default port
    engine_port=$(grep "APP_PORT = " engine-${engine_dir##*/}.py | cut -d'=' -f2 | sed 's/^ *//g')
    docker stop ${engine_dir##*/}-docker-001
    docker run -t -d --rm -p $engine_port:$engine_port --name="${engine_dir##*/}-docker-001" -v $engines_path/${engine_dir##*/}/${engine_dir##*/}.json:/opt/patrowl-engines/${engine_dir##*/}/${engine_dir##*/}.json:ro patrowl-${engine_dir##*/}
    fi
done
