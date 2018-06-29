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


curpwd=${PWD}
engine_path="${PWD}/../engines" # change the path if needed

for engine in ${engine_path}/*; do
  if [ -f "${engine}/Dockerfile" ]; then
    cd ${engine}
    echo -n "Building 'patrowl-${engine##*/}' docker image..."
    docker build --rm --quiet --tag "patrowl-${engine##*/}" . &
    spinner $!
    echo "Done."
  fi
done

cd ${curpwd}
exit 0
