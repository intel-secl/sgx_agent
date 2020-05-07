#!/bin/bash

SGX_DCAP_REPO="https://github.com/intel/SGXDataCenterAttestationPrimitives.git"
GIT_CLONE_PATH=/tmp/dataCenterAttestationPrimitives

install_sgx_components()
{
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

								cd $GIT_CLONE_PATH/tools/PCKRetrievalTool
								git apply $path/remove_pccs_connect.diff
								make clean all || exit 1
								make || exit 1
								cp libdcap_quoteprov.so.1 enclave.signed.so /
								cp PCKIDRetrievalTool /usr/sbin/
}

install_sgx_components
