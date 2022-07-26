To use docker-slim, install it following the instructions at : https://github.com/docker-slim/docker-slim
then edit the engines_list variable inside PatrowlEngines/docker-slim.sh file to have only the engines  you want.
then run it :
- it will build the engine
- run it
- docker-slim to probe the running container
- create the slim image
- remove the running container
- run a container from the slim image
