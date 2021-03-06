#!/bin/bash

COMPONENT_NAME=sgx_agent
PRODUCT_HOME=/opt/$COMPONENT_NAME
BIN_PATH=$PRODUCT_HOME/bin
LOG_PATH=/var/log/$COMPONENT_NAME
CONFIG_PATH=/etc/$COMPONENT_NAME
CERTS_PATH=$CONFIG_PATH/certs
CERTDIR_TRUSTEDJWTCERTS=$CERTS_PATH/trustedjwt
CERTDIR_TRUSTEDCAS=$CERTS_PATH/trustedca

if [ ! -f $CONFIG_PATH/.setup_done ]; then
  for directory in $LOG_PATH $CONFIG_PATH $BIN_PATH $CERTS_PATH $CERTDIR_TRUSTEDJWTCERTS $CERTDIR_TRUSTEDCAS; do
    mkdir -p $directory
    if [ $? -ne 0 ]; then
      echo "Cannot create directory: $directory"
      exit 1
    fi
    chown -R $COMPONENT_NAME:$COMPONENT_NAME $directory
    chmod 700 $directory
    chmod g+s $directory
  done
  sgx_agent setup all
  if [ $? -ne 0 ]; then
    exit 1
  fi
  touch $CONFIG_PATH/.setup_done
fi
# to get actual hostname inside the container
cp /etc/hostname /proc/sys/kernel/hostname

if [ ! -z $SETUP_TASK ]; then
  IFS=',' read -ra ADDR <<< "$SETUP_TASK"
  for task in "${ADDR[@]}"; do
    sgx_agent setup $task --force
    if [ $? -ne 0 ]; then
      exit 1
     fi
  done
fi

sgx_agent run
