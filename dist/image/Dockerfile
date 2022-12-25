# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

FROM ubuntu:focal
LABEL org.label-schema.name="SGX Agent" \
     org.label-schema.vendor="Intel Corporation" \
     org.label-schema.license="BSD-3-Clause" \
     org.label-schema.url="https://github.com/intel-secl/intel-secl"

# Set env variables
ENV SGX_AGENT_BIN dist/image/bin
COPY dist/image/create_roles.sh /create_roles.sh
RUN chmod +x /create_roles.sh

##Install PCK Id retrival tool
RUN apt update -y
RUN apt-get install -y dmidecode wget gnupg curl ca-certificates openssl
RUN apt install dpkg-dev gzip -y
RUN wget -v https://download.01.org/intel-sgx/sgx-linux/2.17/distro/ubuntu20.04-server/sgx_debian_local_repo.tgz
RUN tar -xvf sgx_debian_local_repo.tgz
RUN echo "deb [trusted=yes] file:/ ./" | tee  /etc/apt/sources.list.d/intel-sgx.list
RUN cat /etc/apt/sources.list.d/intel-sgx.list
RUN dpkg-scanpackages . /dev/null | gzip -9c > Packages.gz
RUN apt update -y
RUN apt install -y sgx-pck-id-retrieval-tool
RUN ls /opt/intel/sgx-pck-id-retrieval-tool/

RUN cp /opt/intel/sgx-pck-id-retrieval-tool/PCKIDRetrievalTool /usr/bin/
RUN cp /opt/intel/sgx-pck-id-retrieval-tool/libsgx_id_enclave.signed.so* /usr/bin/
RUN cp /opt/intel/sgx-pck-id-retrieval-tool/libsgx_pce.signed.so* /usr/bin/
RUN sed -i 's/^\(PCCS_URL.*\)/#\1/g' /opt/intel/sgx-pck-id-retrieval-tool/network_setting.conf

# COPY $SGX_AGENT_BIN/libdcap_quoteprov.so.1 $SGX_AGENT_BIN/pck_id_retrieval_tool_enclave.signed.so /usr/sbin/
RUN apt install -y libsgx-dcap-ql libsgx-ra-uefi
RUN apt-get clean && apt-get autoclean
COPY out/sgx_agent /usr/bin/sgx_agent

COPY dist/image/entrypoint.sh /entrypoint.sh
RUN touch /.container-env && chmod +x /entrypoint.sh
ENTRYPOINT ["./entrypoint.sh"]