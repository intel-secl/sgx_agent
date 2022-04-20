# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

FROM ubuntu:focal

LABEL org.label-schema.name="SGX Agent" \
      org.label-schema.vendor="Intel Corporation" \
      org.label-schema.license="BSD-3-Clause" \
      org.label-schema.url="https://github.com/intel-secl/intel-secl"

# Set env variables
ENV SGX_AGENT_BIN dist/image/bin
ENV SGX_LIBS_REPO='deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu/ focal main'

COPY dist/image/create_roles.sh /create_roles.sh
RUN chmod +x /create_roles.sh

COPY $SGX_AGENT_BIN/libdcap_quoteprov.so.1 $SGX_AGENT_BIN/pck_id_retrieval_tool_enclave.signed.so /usr/sbin/
COPY $SGX_AGENT_BIN/PCKIDRetrievalTool /usr/sbin/

RUN apt-get update -y
RUN apt-get install -y dmidecode wget gnupg curl ca-certificates openssl

RUN echo $SGX_LIBS_REPO | tee /etc/apt/sources.list.d/intel-sgx.list
RUN wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -
RUN apt-get update -y
RUN apt-get install -y libsgx-dcap-ql libsgx-ra-uefi
RUN apt-get clean && apt-get autoclean

COPY out/sgx_agent /usr/bin/sgx_agent
COPY dist/image/entrypoint.sh /entrypoint.sh
RUN touch /.container-env && chmod +x /entrypoint.sh
ENTRYPOINT ["./entrypoint.sh"]