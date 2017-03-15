#!/bin/bash

set -e

DOCKER_TAG=sqltest:$1

# Rebuild the docker image. We need to copy the runner to the base folder so it
# can be loaded into the image.
docker build -t $DOCKER_TAG ${1//.//}

# Remove any exiting container
if [[ $(docker ps -aqf "name=$1") ]]; then
    docker rm -f $(docker ps -aqf "name=$1")
fi

# Run the container with the default command.
docker run -d --name $1 -v "`pwd`:/tmp/sql" $DOCKER_TAG

# We have to give the container a bit of time to start up. There should be a
# better solution here.
sleep 30

# Execute the tests
docker exec $(docker ps -aqf "name=$1") \
    /bin/sh -c "cd /tmp/sql && python generate_tests.py $1"
