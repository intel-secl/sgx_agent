/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
	"intel/isecl/lib/common/v5/setup"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoad(t *testing.T) {
	temp, _ := ioutil.TempFile("", "config.yml")
	temp.WriteString("cmsbaseurl: https://<cms.server.com>:8445/cms/v1/\nsgx_agent:\n")
	defer os.Remove(temp.Name())
	c := Load(temp.Name())
	assert.Equal(t, "https://<cms.server.com>:8445/cms/v1/", c.CMSBaseURL)
}

func TestSave(t *testing.T) {
	temp, _ := ioutil.TempFile("", "config.yml")
	defer os.Remove(temp.Name())
	c := Load(temp.Name())
	c.CMSBaseURL = "https://<cms.server.com>:8445/cms/v2/"
	c.Save()
	c2 := Load(temp.Name())
	assert.Equal(t, "https://<cms.server.com>:8445/cms/v2/", c2.CMSBaseURL)

	c.configFile = "/hpt/nofile"
	err := c.Save()
	assert.Error(t, err)

	c.configFile = ""
	err = c.Save()
	assert.Error(t, err)
}

func TestGlobal(t *testing.T) {
	GlobalConfig = Global()
	assert.NotEmpty(t, GlobalConfig)
}

func TestSaveConfiguration(t *testing.T) {
	temp, _ := ioutil.TempFile("", "config.yml")
	defer os.Remove(temp.Name())
	c := Load(temp.Name())
	var ctx setup.Context
	err := c.SaveConfiguration("all", ctx)
	assert.NotEmpty(t, err)

	c.CmsTLSCertDigest = "abcdefghijklmnopqrstuvwxyz1234567890"

	c.CMSBaseURL = ""
	err = c.SaveConfiguration("all", ctx)
	assert.NotEmpty(t, err)

	c.CMSBaseURL = "https://cms.com/cms/v1"
	err = c.SaveConfiguration("all", ctx)
	assert.Empty(t, err)

	// Read from env.
	os.Setenv("CMS_TLS_CERT_SHA384", "abcdefghijklmnopqrstuvwxyz1234567890")
	os.Setenv("CMS_BASE_URL", "https://cms.com/cms/v1")
	os.Setenv("SHVS_TLS_CERT_CN", "TEST COMMON NAME")
	os.Setenv("KEY_PATH", "test/tls.key")
	os.Setenv("CERT_PATH", "test/tls-cert.pem")
	os.Setenv("SAN_LIST", "test")
	err = c.SaveConfiguration("all", ctx)
	assert.Empty(t, err)

	os.Setenv("CMS_BASE_URL", "https://cms.com/cms/v1%+o")
	err = c.SaveConfiguration("all", ctx)
	assert.NotEmpty(t, err)
}
