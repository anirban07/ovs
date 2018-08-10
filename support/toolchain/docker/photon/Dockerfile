FROM vmware/photon:2.0
MAINTAINER Prasoon Telang <telangp@vmware.com>
USER root
ENV PYTHONDONTWRITEBYTECODE yes
RUN mkdir /var/log/ovs-custom
RUN rm -rf /var/log/ovs-custom/*
RUN mkdir /etc/depmod.d
RUN tdnf erase -y toybox

RUN tdnf install --refresh -y -q rpm-4.13.0.1 \
                                 sed-4.4 \
                                 createrepo_c-0.10.0 \
                                 procps-ng-3.3.12 \
                                 shadow-4.2.1 \
                                 binutils-2.29.1 \
                                 cyrus-sasl \
                                 make-4.2.1 \
                                 gawk-4.1.4 \
                                 git-2.14.2 \
                                 tar-1.29 \
                                 gzip-1.8 \
                                 zip-3.0 \
                                 unzip-6.0 \
                                 autoconf-2.69 \
                                 automake-1.15 \
                                 libtool-2.4.6 \
                                 libcap-ng-devel \
                                 openldap \
                                 python-pip-9.0.1 \
                                 diffutils \
                                 findutils \
                                 file \
                                 elfutils-0.169 \
                                 gcc-6.3.0 \
                                 glibc-devel-2.26 \
                                 linux-api-headers-4.9.74 \
                                 util-linux-devel-2.29.2 \
                                 e2fsprogs-devel-1.43.4 \
                                 rpm-build-4.13.0.1 \
                                 rpm-devel-4.13.0.1 \
                                 jansson-devel-2.10 \
                                 openssl-1.0.2n \
                                 openssl-devel-1.0.2n \
                                 zlib-1.2.11 \
                                 zlib-devel-1.2.11 \
                                 lightwave-client-1.3.1 \
                                 vim \
                                 rsync-3.1.2 && \
    tdnf clean all && \
    pip install six
