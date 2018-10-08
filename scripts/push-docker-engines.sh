#!/bin/bash

curpwd=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
engine_path="${curpwd}/../engines" # change the path if needed

docker login

for engine in ${engine_path}/*; do
  if [ -f "${engine}/Dockerfile" ]; then
    cd ${engine}
    cp -Rf ../utils/ utils/
    echo -n "Tag 'patrowl-${engine##*/}' docker image..."
    docker tag patrowl-${engine##*/} patrowl/patrowl-${engine##*/}
    echo -n "Push 'patrowl-${engine##*/}' docker image to the container repo"
    docker push patrowl/patrowl-${engine##*/}
    echo "Done."
  fi
done

cd ${curpwd}
exit 0
