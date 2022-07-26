get_engine_port() {
    engine=$1
    port=$(grep "EXPOSE 5" engines/$engine/Dockerfile | awk  '{print $2}')
    echo $port
}

docker_build_and_run() {
    engine=$1
    port=$(get_engine_port $engine)
    docker build -t $engine -f engines/$engine/Dockerfile engines/$engine/
    docker run -d -p $port:$port $engine
    docker-slim build --http-probe=false --exec "python3 tests/*" $engine
    remove_container_from_image $engine
    slim_engine="${engine}.slim"
    docker run -d -p $port:$port $slim_engine
}

remove_container_from_image() {
    docker ps -a | awk '{ print $1,$2 }' | grep $1 | awk '{print $1 }' | xargs -I {} docker rm -f {}
}


engine_list="apivoid
arachni
certstream
cortex
cybelangel
droopescan
eyewitness
nessus
nmap
openvas
owl_code
owl_dns
owl_leaks
owl_request
pastebin_monitor
shhgit
ssllabs
sslscan
urlvoid
virustotal
wpscan"

engine_list="apivoid
owl_dns"

for i in $engine_list; 
    do docker_build_and_run $i;
done


