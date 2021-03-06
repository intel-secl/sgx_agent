# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

FROM centos:8

# Set env variables
ENV SGX_AGENT_BIN dist/image/bin

COPY $SGX_AGENT_BIN/sgx_rpm_local_repo ${PWD}/sgx_rpm_local_repo
COPY $SGX_AGENT_BIN/libdcap_quoteprov.so.1 $SGX_AGENT_BIN/pck_id_retrieval_tool_enclave.signed.so /usr/sbin/ 
COPY $SGX_AGENT_BIN/PCKIDRetrievalTool /usr/sbin/
COPY $SGX_AGENT_BIN/libsgx-ra-uefi-1.10.100.4-1.el8.x86_64.rpm $PWD

RUN dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
RUN dnf install -y yum-utils dmidecode

RUN yum-config-manager --add-repo file://$PWD/sgx_rpm_local_repo && \
    dnf install -y --nogpgcheck libsgx-dcap-ql && \
    rm -rf sgx_rpm_local_repo /etc/yum.repos.d/*sgx_rpm_local_repo.repo

RUN rpm -ivh libsgx-ra-uefi-1.10.100.4-1.el8.x86_64.rpm

RUN useradd -u 1001 --comment "SGX Agent Service" --home /opt/sgx_agent  --shell /bin/false sgx_agent
COPY out/sgx_agent /usr/bin/sgx_agent
COPY dist/image/entrypoint.sh /entrypoint.sh
RUN chmod 700 /entrypoint.sh
ENTRYPOINT ["./entrypoint.sh"]
