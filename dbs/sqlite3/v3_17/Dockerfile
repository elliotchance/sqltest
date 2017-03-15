FROM ubuntu:14.04

RUN apt-get update
RUN apt-get install -y wget unzip lib32z1 python python-pip
RUN pip install pyyaml

RUN wget https://www.sqlite.org/2017/sqlite-tools-linux-x86-3170000.zip
RUN unzip sqlite-tools-linux-x86-3170000.zip

# This just keeps the container running since SQLite3 isn't a service.
CMD tail -F -n0 /etc/hosts
