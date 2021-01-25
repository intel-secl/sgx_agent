/*
* Copyright (C) 2020 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"github.com/pkg/errors"

	"intel/isecl/lib/clients/v3"
	"intel/isecl/sgx_agent/v3/config"
	"intel/isecl/sgx_agent/v3/constants"
	"intel/isecl/sgx_agent/v3/utils"

	"io/ioutil"
	"net/http"
	"encoding/json"
	"bytes"
	"strings"
	"strconv"
	"time"
)

var (
	hardwareUUIDCmd = []string{"dmidecode", "-s", "system-uuid"}
)

func UpdateSHVSPeriodically (sgxdiscovery *SGX_Discovery_Data, platform_data *Platform_Data, period int) error {
	//First Update
	tcbstatus , err := GetTCBStatus(platform_data.Qe_id)
	if err != nil {
		log.WithError(err).Error("Unable to get TCB Status from SCS.")
	} else {
		tcbUptoDate, _ := strconv.ParseBool(tcbstatus)
		err = PushHostSGXDiscovery(sgxdiscovery, tcbUptoDate)
		if err != nil {
			log.WithError(err).Error("Unable to update SHVS.")
		}
	}

	//Subsequent Updates
	for {
		//Sleep here on a timer.
		//FIXME : Better message
		log.Infof ("Waiting for %v minutes until next update.", period)
		time.Sleep(time.Duration(period) * time.Minute)
		
		tcbstatus , err := GetTCBStatus(platform_data.Qe_id)
		if err != nil {
			log.WithError(err).Error("Unable to get TCB Status from SCS.")
		} else {
			tcbUptoDate, _ := strconv.ParseBool(tcbstatus)
			err = PushHostSGXDiscovery(sgxdiscovery, tcbUptoDate)
			if err != nil {
				log.WithError(err).Error("Unable to update SHVS.")
			}
		}
	}
	return nil
}

//FIXME : Shouldn't be using a copy from SHVS
type SGXHostInfo struct{
	HostName         string `json:"host_name"`
	Description      string `json:"description, omitempty"`
	UUID             string `json:"uuid"`
	SgxSupported   bool      `json:"sgx_supported"`
	SgxEnabled     bool      `json:"sgx_enabled"`
	FlcEnabled     bool      `json:"flc_enabled"`
	EpcOffset          string    `json:"epc_offset"`
	EpcSize        string    `json:"epc_size"`
	TcbUptodate    bool      `json:"tcb_upToDate"`
}

func PushHostSGXDiscoveryRepeatUntilSuccess(sgxdiscovery *SGX_Discovery_Data, tcbstatus bool) error {
	conf := config.Global()
	if conf == nil {
		return errors.Wrap(errors.New("pushHostSGXDiscovery: Configuration pointer is null"), "Config error")
	}

	err := PushHostSGXDiscovery (sgxdiscovery, tcbstatus)

	var time_bw_calls int = conf.WaitTime
	var retries int = 0
	if (err != nil) {
		log.WithError (err)
		for {
			err = PushHostSGXDiscovery (sgxdiscovery, tcbstatus)
			if err == nil {
				return err //Exit out of this loop
			}

			retries += 1
			if retries >= conf.RetryCount {
				log.Errorf("pushHostSGXDiscovery: Retried %d times, Sleeping %d minutes...", conf.RetryCount, time_bw_calls)
				time.Sleep(time.Duration(time_bw_calls) * time.Minute)
				retries = 0
			}
		}
	}
	return err
}


func PushHostSGXDiscovery(sgxdiscovery *SGX_Discovery_Data, tcbstatus bool) error {
	log.Trace("resource/UpdateHostSGXDiscovery Entering")
	defer log.Trace("resource/UpdateHostSGXDiscovery Leaving")



	conf := config.Global()
	if conf == nil {
		return errors.Wrap(errors.New("UpdateHostSGXDiscovery: Configuration pointer is null"), "Config error")
	}

	api_endpoint := conf.SGXHVSBaseUrl + "/hosts"
	log.Debug ("Updating SGX Discovery data to ", api_endpoint)
	//Hardware UUID
	result, err := utils.ReadAndParseFromCommandLine(hardwareUUIDCmd)
	if err != nil {
		return errors.Wrap(err, "UpdateHostSGXDiscovery  - Could not parse hardware UUID")
	}
	hardwareUUID := ""
	for i := range result {
		hardwareUUID = strings.TrimSpace(result[i])
		break
	}

	//Get Host Name
	hostName, err := utils.GetLocalHostname()
	if err != nil {
		return errors.Wrap(err, "UpdateHostSGXDiscovery - Error while getting Local hostName address")
	}

	requestData := SGXHostInfo{
		HostName: hostName,
		Description: "Demo",
		UUID: hardwareUUID,
		SgxSupported: sgxdiscovery.Sgx_supported,
		SgxEnabled: sgxdiscovery.Sgx_enabled,
		FlcEnabled: sgxdiscovery.Flc_enabled,
		EpcOffset: sgxdiscovery.Epc_startaddress,
		EpcSize: sgxdiscovery.Epc_size,
		TcbUptodate: true}
		
	reqBytes, err := json.Marshal(requestData)
	if err != nil {
		return errors.Wrap(err, "UpdateHostSGXDiscovery: struct to json marshalling failed")
	}

	//FIXME : Check for URL
	request, _ := http.NewRequest("POST", api_endpoint, bytes.NewBuffer(reqBytes))
	request.Header.Set("Content-Type", "application/json")
	err = utils.AddJWTToken(request)
	if err != nil {
		return errors.Wrap(err, "UpdateHostSGXDiscovery: Failed to add JWT token to the authorization header")
	}

	client, err := clients.HTTPClientWithCADir(constants.TrustedCAsStoreDir)
	if err != nil {
		log.WithError(err).Error("resource/update_shvs:UpdateHOSTSGXDiscovery() Error while creating http client")
		return errors.Wrap(err, "resource/update_shvs:UpdateHOSTSGXDiscovery() Error while creating http client")
	}

	log.Debug ("Client Created.")

	httpClient := &http.Client{
		Transport: client.Transport,
	}

	response, err := httpClient.Do(request)
	if response != nil {
		defer func() {
			derr := response.Body.Close()
			if derr != nil {
				log.WithError(derr).Error("Error closing response")
			}
		}()
	}
	if err != nil {
		slog.WithError(err).Error("resource/UpdateHostSGXDiscovery Error making request")
		return errors.Wrapf(err, "resource/UpdateHostSGXDiscovery Error making request %s", api_endpoint)
	}

	log.Debug ("Request Completed : ", response.StatusCode)


	if (response.StatusCode != http.StatusOK) && (response.StatusCode != http.StatusCreated) {
		return errors.Errorf("resource/UpdateHostSGXDiscovery Request made to %s returned status %d", api_endpoint, response.StatusCode)
	}

	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return errors.Wrap(err, "resource/UpdateHostSGXDiscovery Error reading response")
	}

	log.Debugf("Response from SHVS: -%v", string(data))

	return nil
}
