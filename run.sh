#!/bin/bash

set -e

DOCKER_TAG=sql:postgresql-9.2

docker build -t $DOCKER_TAG dbs/PostgreSQL/9.2
docker run -d -p 5432:5432 --name postgresql-9.2 -v "`pwd`:/tmp/sql" $DOCKER_TAG -d pos
