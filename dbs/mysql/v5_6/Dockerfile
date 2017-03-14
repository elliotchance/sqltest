FROM mysql:5.6

RUN apt-get update
RUN apt-get install -y python-psycopg2 python-pip libyaml-dev libpython2.7-dev
RUN pip install pyyaml mysql-connector

ENV MYSQL_ALLOW_EMPTY_PASSWORD=1
ENV MYSQL_DATABASE=test
