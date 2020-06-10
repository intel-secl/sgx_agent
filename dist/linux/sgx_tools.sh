#!/bin/bash

SGX_DCAP_REPO="https://github.com/intel/SGXDataCenterAttestationPrimitives.git"
GIT_CLONE_PATH=/tmp/dataCenterAttestationPrimitives
SGX_DCAP_RPM_VER=1.6.90.2-1

install_sgx_components()
{
	#install msr-tools
	which rdmsr
	x=`echo $?`
	if [ $x -ne 0 ]
	then
		yum localinstall -y http://rpmfind.net/linux/fedora/linux/releases/30/Everything/x86_64/os/Packages/m/msr-tools-1.3-11.fc30.x86_64.rpm
	else
		echo "rdmsr present. Continuing...."
	fi
	rm -rf $GIT_CLONE_PATH

	mkdir -p $GIT_CLONE_PATH
	pushd  $GIT_CLONE_PATH
	echo "Please provide patch file path"
	read path
	echo $path
	ls $path/remove_pccs_connect.diff
	status=$?
	if test $status -ne 0
	then
		echo "file not found on the given path"
		exit 1
	fi

	git clone $SGX_DCAP_REPO $GIT_CLONE_PATH/
	cp $path/remove_pccs_connect.diff $GIT_CLONE_PATH/

	#Build Registration Service
	cd $GIT_CLONE_PATH/tools/SGXPlatformRegistration
	source /opt/intel/sgxsdk/environment
	make clean || exit 1
	make || exit 1
	make rpm_pkg
	cd ./build/installer
	rpm -e libsgx-ra-uefi-devel-${SGX_DCAP_RPM_VER}.el8.x86_64 libsgx-ra-uefi-${SGX_DCAP_RPM_VER}.el8.x86_64 sgx-ra-service-${SGX_DCAP_RPM_VER}.el8.x86_64 libsgx-ra-network-devel-${SGX_DCAP_RPM_VER}.el8.x86_64 libsgx-ra-network-${SGX_DCAP_RPM_VER}.el8.x86_64
	rpm -ivh libsgx-ra-uefi-devel-${SGX_DCAP_RPM_VER}.el8.x86_64.rpm libsgx-ra-network-${SGX_DCAP_RPM_VER}.el8.x86_64.rpm libsgx-ra-uefi-${SGX_DCAP_RPM_VER}.el8.x86_64.rpm sgx-ra-service-${SGX_DCAP_RPM_VER}.el8.x86_64.rpm

	#Build PCKRetrievalTool
	cd $GIT_CLONE_PATH/tools/PCKRetrievalTool
	git apply $path/remove_pccs_connect.diff
	make clean || exit 1
	make MPA=1 || exit 1
	cp -u libdcap_quoteprov.so.1 enclave.signed.so /
	cp -u PCKIDRetrievalTool /usr/sbin/
}

install_sgx_components
