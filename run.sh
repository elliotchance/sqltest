#!/bin/bash

set -e

DOCKER_TAG=sql:$1

docker build -t $DOCKER_TAG ${1//.//}
docker run -d -p 5432:5432 --name $1 -v "`pwd`:/tmp/sql" $DOCKER_TAG -d pos || true

python generate_tests.py $1
