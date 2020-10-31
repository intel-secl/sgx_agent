/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package utils

import (
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"intel/isecl/lib/clients/v3"
	"intel/isecl/lib/clients/v3/aas"
	"intel/isecl/sgx_agent/v3/config"
	"intel/isecl/sgx_agent/v3/constants"
	"net/http"
	"os/exec"
	"strings"
	"sync"
)

var (
	c         = config.Global()
	AasClient = aas.NewJWTClient(c.AuthServiceUrl)
	AasRWLock = sync.RWMutex{}
)

var statusUpdateLock *sync.Mutex

func init() {
	AasRWLock.Lock()
	defer AasRWLock.Unlock()
	if AasClient.HTTPClient == nil {
		c, err := clients.HTTPClientWithCADir(constants.TrustedCAsStoreDir)
		if err != nil {
			return
		}
		AasClient.HTTPClient = c
	}
}

func ReadAndParseFromCommandLine(input []string) ([]string, error) {
	cmd := exec.Command(input[0], input[1:]...)
	out, err := cmd.CombinedOutput()
	result := strings.Split(string(out), "\n")
	cleanedResult := deleteEmptyFromSlice(result)
	return cleanedResult, err
}

func deleteEmptyFromSlice(s []string) []string {
	r := make([]string, 0)
	for i := range s {
		trimmed := strings.TrimSpace(s[i])
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if trimmed != "" {
			r = append(r, trimmed)
		}
	}
	return r
}

func AddJWTToken(req *http.Request) error {
	log.Trace("resource/utils:AddJWTToken() Entering")
	defer log.Trace("resource/utils:AddJWTToken() Leaving")

	if AasClient.BaseURL == "" {
		AasClient = aas.NewJWTClient(c.AuthServiceUrl)
		if AasClient.HTTPClient == nil {
			c, err := clients.HTTPClientWithCADir(constants.TrustedCAsStoreDir)
			if err != nil {
				return errors.Wrap(err, "resource/utils:AddJWTToken() Error initializing http client")
			}
			AasClient.HTTPClient = c
		}
	}
	AasRWLock.RLock()
	jwtToken, err := AasClient.GetUserToken(c.SGX_AgentUserName)
	AasRWLock.RUnlock()
	// something wrong
	if err != nil {
		// lock aas with w lock
		AasRWLock.Lock()
		defer AasRWLock.Unlock()
		// check if other thread fix it already
		jwtToken, err = AasClient.GetUserToken(c.SGX_AgentUserName)
		// it is not fixed
		if err != nil {
			AasClient.AddUser(c.SGX_AgentUserName, c.SGX_AgentPassword)
			err = AasClient.FetchAllTokens()
			jwtToken, err = AasClient.GetUserToken(c.SGX_AgentUserName)
			if err != nil {
				return errors.Wrap(err, "resource/utils:AddJWTToken() Could not fetch token")
			}

		}
	}
	log.Debug("resource/utils:AddJWTToken() successfully added jwt bearer token")
	req.Header.Set("Authorization", "Bearer "+string(jwtToken))
	return nil
}
