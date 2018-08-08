FROM ubuntu:18.04
MAINTAINER "Prasoon Telang" <telangp@vmware.com>
ENV container=docker
VOLUME ["/sys/fs/cgroup"]
CMD ["/sbin/init"]

RUN apt update -y && \
    apt install -y autoconf \
                   libcap-ng-dev \
                   libldap2-dev \
                   libsasl2-dev \
                   libssl-dev \
                   libtool \
                   make \
                   python-pip \
                   vim \
                   rsync && \
    pip install six
