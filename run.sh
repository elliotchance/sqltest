#!/bin/bash

set -e

DOCKER_TAG=sqltest:$1

# Rebuild the docker image. We need to copy the runner to the base folder so it
# can be loaded into the image.
docker build -t $DOCKER_TAG ${1//.//}

# Run the container, we always run a fresh one.
docker rm -f $(docker ps -aqf "name=$1")

docker run -d --name $1 -v "`pwd`:/tmp/sql" $DOCKER_TAG postgres
sleep 5

docker exec $(docker ps -aqf "name=$1") \
    /bin/sh -c "cd /tmp/sql; python generate_tests.py $1"
