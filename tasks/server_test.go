/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tasks

import (
	//"intel/isecl/lib/common/setup"
	//"intel/isecl/sgx_agent/config"
	//	"os"

	//"github.com/stretchr/testify/assert"
	"testing"
)

func TestServerSetupEnv(t *testing.T) {
	log.Trace("tasks/server_test:TestServerSetupEnv() Entering")
	defer log.Trace("tasks/server_test:TestServerSetupEnv() Leaving")

	///Since right now SGX Agent is not a https server this all is not needed.
	/*os.Setenv("CMS_PORT", "1337")
	os.Setenv("CMS_KEY_ALGORITHM", "RSA")
	os.Setenv("CMS_KEY_LENGTH", "3072")
	os.Setenv("AAS_API_URL", "https://192.178.182.1:1337/aas")
	c := config.Configuration{}
	s := Server{
		Flags:         nil,
		Config:        &c,
		ConsoleWriter: os.Stdout,
	}
	ctx := setup.Context{}
	s.Run(ctx)
	assert.Equal(t, 1337, c.Port)
	assert.Equal(t, "RSA", c.KeyAlgorithm)
	*/

}
