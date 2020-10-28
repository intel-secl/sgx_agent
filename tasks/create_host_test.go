/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"github.com/stretchr/testify/assert"
	"intel/isecl/lib/common/v3/setup"
	"intel/isecl/sgx_agent/v3/config"
	"io/ioutil"
	"os"
	"testing"
)

func TestCreateHost(t *testing.T) {
	log.Trace("tasks/tls_test:TestTlsCertCreation() Entering")
	defer log.Trace("tasks/tls_test:TestTlsCertCreation() Leaving")

	assert := assert.New(t)

	temp, _ := ioutil.TempFile("", "config.yml")
	defer os.Remove(temp.Name())
	c := config.Load(temp.Name())

	ca := CreateHost{
		Flags:         nil,
		ConsoleWriter: os.Stdout,
		Config:        c,
	}

	ctx := setup.Context{}
	err := ca.Run(ctx)
	assert.NoError(err)
}
