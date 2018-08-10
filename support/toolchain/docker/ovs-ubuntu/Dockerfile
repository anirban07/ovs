FROM ubuntu:18.04
MAINTAINER "Prasoon Telang" <telangp@vmware.com>
ENV container=docker

USER root
RUN apt update -y && \
    apt install -y autoconf \
                   libcap-ng-dev \
                   libldap2-dev \
                   libsasl2-dev \
                   libssl-dev \
                   libtool \
                   make \
                   python-pip \
                   rsync && \
    pip install six
