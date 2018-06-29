#!/bin/bash

CWD=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
engines_path="$CWD/../engines" # change the path if needed
docker_port=5100

for engine_dir in $engines_path/*; do
  if [ -f "${engine_dir}/Dockerfile" -a -f "${engine_dir}/${engine_dir##*/}.json" ]; then
    #echo $engine_dir
    cd $engine_dir
    # get the default port
    engine_port=$(grep "APP_PORT = " engine-${engine_dir##*/}.py | cut -d'=' -f2 | sed 's/^ *//g')
    docker stop ${engine_dir##*/}-docker-001
    docker run -d --rm -p 1$engine_port:$engine_port --name="${engine_dir##*/}-docker-001" -v $engines_path/${engine_dir##*/}/${engine_dir##*/}.json:/opt/patrowl-engines/${engine_dir##*/}/${engine_dir##*/}.json:ro patrowl-${engine_dir##*/}
    fi
done
