/*
* Copyright (C) 2019 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"intel/isecl/lib/clients"
	commLog "intel/isecl/lib/common/log"
	"intel/isecl/lib/common/setup"
	"intel/isecl/sgx_agent/config"
	"intel/isecl/sgx_agent/constants"
	"intel/isecl/sgx_agent/utils"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
)

var slog = commLog.GetSecurityLogger()

type CreateHost struct {
	Flags         []string
	Config        *config.Configuration
	ConsoleWriter io.Writer
	ip            string
}

type Host struct {
	HostName         string `json:"host_name"`
	Description      string `json:"description"`
	ConnectionString string `json:"connection_string"`
	HardwareUUID     string `json:"uuid"`
	Flag             bool   `json:"overwrite"`
}

var (
	hardwareUUIDCmd = []string{"dmidecode", "-s", "system-uuid"}
)

//
// Registers (or updates) HVS with information about the currenct compute
// node (providing the connection string, hostname (ip addr) and tls policy).
//
// If the host already exists, create-host will return an error.
//
func (task CreateHost) Run(c setup.Context) error {
	log.Trace("tasks/create_Host:Run() Entering")
	defer log.Trace("tasks/create_Host:Run() Leaving")

	var err error
	var host_info, host_info1 Host

	task.ip, err = utils.GetLocalIpAsString()
	if err != nil {
		return errors.Wrap(err, "tasks/create_host:Run() Error while getting Local IP address")
	}

	connectionString, err := utils.GetConnectionString(task.Config)
	if err != nil {
		return err
	}
	host_info.HostName = task.ip
	host_info.Description = "demo"
	host_info.ConnectionString = connectionString + "/host"
	host_info.Flag = true
	result, err := utils.ReadAndParseFromCommandLine(hardwareUUIDCmd)
	if err != nil {
		return errors.Wrap(err, "tasks/create_hosts:Run() Could not parse hardware UUID")
	}

	hardwareUUID := ""
	for i := range result {
		hardwareUUID = strings.TrimSpace(result[i])
		break
	}
	host_info.HardwareUUID = hardwareUUID

	///Now connect to SGX-HVS with all this information.
	HVSUrl := task.Config.SGXHVSBaseUrl
	jsonData, err := json.Marshal(host_info)
	if err != nil {
		return errors.Wrap(err, "tasks/create_hosts:Run() Could not marshal data from SGX TA")
	}

	url := fmt.Sprintf("%s/hosts", HVSUrl)
	request, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+task.Config.BearerToken)
	client, err := clients.HTTPClientWithCADir(constants.TrustedCAsStoreDir)
	if err != nil {
		log.WithError(err).Error("vsclient/vsclient_factory:createHttpClient() Error while creating http client")
		return nil
	}

	httpClient := &http.Client{
		Transport: client.Transport,
	}

	slog.Info("CreateHost: Posting to url, json: ", url, string(jsonData))

	response, err := httpClient.Do(request)
	if err != nil {
		return errors.Wrapf(err, "tasks/create_Host:Run() Error making request %s", url)
	}

	defer response.Body.Close()

	if (response.StatusCode != http.StatusOK) && (response.StatusCode != http.StatusCreated) {
		return errors.Errorf("tasks/create_Host: Run() Request made to %s returned status %d", url, response.StatusCode)
	}

	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return errors.Wrap(err, "tasks/create_Host: Run() Error reading response")
	}

	log.Info("CreateHost returned json: ", string(data))

	err = json.Unmarshal(data, &host_info1)
	if err != nil {
		return errors.Wrap(err, "tasks/create_Host: Run() Error while unmarshaling the response")
	}
	return nil
}

// Using the ip address, query HVS to verify if this host is registered
func (task CreateHost) Validate(c setup.Context) error {
	log.Trace("tasks/CreateHost :Validate() Entering")
	defer log.Trace("tasks/CreateHost:Validate() Leaving")
	return nil
}
