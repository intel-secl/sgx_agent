/*
* Copyright (C) 2019 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"intel/isecl/lib/common/setup"
	"intel/isecl/sgx_agent/config"
	"intel/isecl/sgx_agent/utils"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
)

type CreateHost struct {
	Flags         []string
	Config        *config.Configuration
	ConsoleWriter io.Writer
}

type Host struct {
	HostName         string `json:"host_name"`
	Description      string `json:"description"`
	ConnectionString string `json:"connection_string"`
	HardwareUUID     string `json:"uuid"`
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
	log.Info("tasks/create_Host:Run() Entering")
	defer log.Info("tasks/create_Host:Run() Leaving")

	var err error
	var host_info, host_info1 Host

	connectionString, err := utils.GetConnectionString(task.Config)
	if err != nil {
		return err
	}
	host_info.HostName = "skchost-sgx-agent"
	host_info.Description = "demo"
	host_info.ConnectionString = connectionString + "/host"
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
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	//request.SetBasicAuth(client.cfg.Username, client.cfg.Password)///Later will be JWT token.

	log.Info("CreateHost: Posting to url, json: ", url, string(jsonData))

	response, err := httpClient.Do(request)
	if err != nil {
		fmt.Errorf("%s request failed with error %s\n", url, err)
		return nil
	}

	defer response.Body.Close()

	if (response.StatusCode != http.StatusOK) && (response.StatusCode != http.StatusCreated) {
		return fmt.Errorf("%s returned status %d", url, response.StatusCode)
	}

	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("Error reading response: %s", err)
	}

	log.Info("CreateHost returned json: ", string(data))

	err = json.Unmarshal(data, &host_info1)
	if err != nil {
		return err
	}
	return nil
}

// Using the ip address, query VS to verify if this host is registered
func (task CreateHost) Validate(c setup.Context) error {
	log.Trace("tasks/CreateHost :Validate() Entering")
	defer log.Trace("tasks/CreateHost:Validate() Leaving")
	return nil
}
