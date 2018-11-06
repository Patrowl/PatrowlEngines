#!/bin/bash
spinner()
{
    local pid=$1
    local delay=0.5
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}


curpwd=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
engine_path="${curpwd}/../engines" # change the path if needed

for engine in ${engine_path}/*; do
  if [ -f "${engine}/Dockerfile" ]; then
    cd ${engine}
    echo -n "Copying utils dir..."
    rm -rf utils && cp -Rf ../utils/ .
    echo -n "Building engine 'patrowl-${engine##*/}' docker image..."
    # if [ $engine = "cortex" ]; then
    #   docker-compose -f tests/patrowl-tests-cortex_docker_compose.yml up -d &
    # else
    docker build --rm --quiet --tag "patrowl-${engine##*/}" . &
    # fi
    spinner $!
    echo "Done."
  fi
done

cd ${curpwd}
exit 0
