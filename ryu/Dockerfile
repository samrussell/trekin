FROM ubuntu:14.04

RUN apt-get update
RUN apt-get install -y python
RUN apt-get install -y python-dev
RUN apt-get install -y build-essential
RUN apt-get install -y libxml2-dev
RUN apt-get install -y libxslt1-dev
RUN apt-get install -y zlib1g-dev
RUN apt-get install -y python-pip

RUN pip install -I six==1.7.0
RUN pip install ryu
