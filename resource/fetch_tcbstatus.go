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

	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"
	"fmt"
)

// Wrapper over GetTCBStatus . Retries in case of error till we succeed.
func GetTCBStatusRepeatUntilSuccess(qeid string) (string, error) {
	conf := config.Global()
	if conf == nil {
		return "", errors.Wrap(errors.New("GetTCBStatus: Configuration pointer is null"), "Config error")
	}

	tcbstatus, err := GetTCBStatus (qeid)

	var time_bw_calls int = conf.WaitTime
	var retries int = 0
	if (err != nil) {
		log.WithError (err)
		for {
			tcbstatus, err = GetTCBStatus (qeid)
			if err == nil {
				return tcbstatus, err
			}

			retries += 1
			if retries >= conf.RetryCount {
				log.Errorf("GetTCBStatus: Retried %d times, Sleeping %d minutes...", conf.RetryCount, time_bw_calls)
				time.Sleep(time.Duration(time_bw_calls) * time.Minute)
				retries = 0
			}
		}
	}
	return tcbstatus, err
}

// Fetches TCB status from SCS using QEID.
func GetTCBStatus(qeid string) (string, error) {
	log.Trace("resource/fetch_tcbstatus:Run() Entering")
	defer log.Trace("resource/fetch_tcbstatus:Run() Leaving")

	log.Debug ("Fetching TCB Status from SCS...")

	status := ""

	conf := config.Global()
	if conf == nil {
		return status, errors.Wrap(errors.New("getTCBStatus: Configuration pointer is null"), "Config error")
	}

	SCSBaseURL := conf.ScsBaseUrl

	//FIXME : Use the new api endpoint /tcbstatus
	fetchURL := SCSBaseURL + "/platforminfo/tcbstatus"
	request, _ := http.NewRequest("GET", fetchURL, nil)

	log.Debug("SCS TCB Fetch URL : " ,fetchURL)

	//Add parameter qeid
	q := request.URL.Query()
	q.Add("qeid", qeid)
	request.URL.RawQuery = q.Encode()

	err := utils.AddJWTToken(request)
	if err != nil {
		return status, errors.Wrap(err, "getTCBStatus: Failed to add JWT token to the authorization header")
	}

	client, err := clients.HTTPClientWithCADir(constants.TrustedCAsStoreDir)
	if err != nil {
		log.WithError(err).Error("resource/fetch_tcbstatus:Run() Error while creating http client")
		return status, errors.Wrap(err, "resource/fetch_tcbstatus:Run() Error while creating http client")
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
		slog.WithError(err).Error("resource/fetch_tcbstatus:Run() Error making request")
		return status, errors.Wrapf(err, "resource/fetch_tcbstatus:Run() Error making request %s", fetchURL)
	}

	log.Debug ("Request Completed : ", response.StatusCode)

	if (response.StatusCode != http.StatusOK) && (response.StatusCode != http.StatusCreated) {
		return status, errors.Errorf("resource/fetch_tcbstatus: Run() Request made to %s returned status %d", fetchURL, response.StatusCode)
	}

	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return status, errors.Wrap(err, "resource/fetch_tcbstatus: Run() Error reading response")
	}

	log.Debugf("SCS Fetch TCBStatus response: -%v", string(data))

	var respBody map[string]interface{}
	err = json.Unmarshal(data, &respBody)
	if err != nil {
		return status, errors.Wrap(err, "resource/fetch_tcbstatus: Run() Error while unmarshaling the response")
	}

	//status = respBody[0]["Status"]
	status = fmt.Sprint(respBody["Status"])
	log.Debug ("TCB Status : " , status)

	return status, nil
}
