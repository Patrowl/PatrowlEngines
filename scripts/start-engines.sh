#!/bin/bash

at_term() {
	echo 'Terminate all pids:'
	for engine_pid in ${pid_list[*]}; do
		echo "Killing PID=$engine_pid ..."
		kill $engine_pid
	done
	exit 0
}
trap at_term INT

pid_list=()
CWD=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
engines_path="$CWD/../engines" # change the path if needed

echo $engines_path
for engine_dir in $engines_path/*; do
  if [ -f "${engine_dir}/${engine_dir##*/}.json" ]; then
    echo $engine_dir
    cd $engine_dir
		env/bin/python engine-${engine_dir##*/}.py &
		pid_list+=($!)
	fi
done

echo "All engines are started. Type 'Ctrl-C' to stop/kill the engine instances"
wait
