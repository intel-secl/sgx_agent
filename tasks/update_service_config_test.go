/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"intel/isecl/lib/common/v5/setup"
	"intel/isecl/sgx_agent/v5/config"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestUpdateServiceConfigInvalidSHVSBaseURL(t *testing.T) {
	os.Setenv("SHVS_BASE_URL", "abcdef")
	c := config.Configuration{
		ScsBaseURL: "https://localhost",
		CMSBaseURL: "https://localhost",
	}
	s := Update_Service_Config{
		Flags:         []string{"-port=1337"},
		Config:        &c,
		ConsoleWriter: os.Stdout,
	}
	ctx := setup.Context{}
	err := s.Run(ctx)
	if err != nil {
		assert.Contains(t, err.Error(), "SHVS_BASE_URL provided is invalid")
	}
}

func TestUpdateServiceConfigInvalidSCSBaseURL(t *testing.T) {
	os.Setenv("SHVS_BASE_URL", "https://localhost")
	os.Setenv("SCS_BASE_URL", "abcdef")
	c := config.Configuration{
		CMSBaseURL: "https://localhost",
	}
	s := Update_Service_Config{
		Flags:         []string{"-port=1337"},
		Config:        &c,
		ConsoleWriter: os.Stdout,
	}
	ctx := setup.Context{}
	err := s.Run(ctx)
	if err != nil {
		assert.Contains(t, err.Error(), "SCS_BASE_URL provided is invalid")
	}
}

func TestUpdateServiceConfigEmptySHVSBaseURL(t *testing.T) {
	os.Setenv("SHVS_BASE_URL", "")
	os.Setenv("SCS_BASE_URL", "https://localhost")
	c := config.Configuration{
		CMSBaseURL: "https://localhost",
	}
	s := Update_Service_Config{
		Flags:         []string{"-port=1337"},
		Config:        &c,
		ConsoleWriter: os.Stdout,
	}
	ctx := setup.Context{}
	err := s.Run(ctx)
	if err != nil {
		assert.Contains(t, err.Error(), "SaveConfiguration() ENV variable not found")
	}
}

func TestUpdateServiceConfigEmptySCSBaseURL(t *testing.T) {
	os.Setenv("SHVS_BASE_URL", "https://localhost")
	os.Setenv("SCS_BASE_URL", "")
	c := config.Configuration{
		CMSBaseURL: "https://localhost",
	}
	s := Update_Service_Config{
		Flags:         []string{"-port=1337"},
		Config:        &c,
		ConsoleWriter: os.Stdout,
	}
	ctx := setup.Context{}
	err := s.Run(ctx)
	if err != nil {
		assert.Contains(t, err.Error(), "SCS_BASE_URL is not defined in environment")
	}
}

func TestUpdateServiceConfigEmptyBearerToken(t *testing.T) {
	os.Setenv("SHVS_BASE_URL", "https://localhost")
	os.Setenv("SCS_BASE_URL", "https://localhost")
	os.Setenv("BEARER_TOKEN", "")
	c := config.Configuration{
		CMSBaseURL: "https://localhost",
	}
	s := Update_Service_Config{
		Flags:         []string{"-port=1337"},
		Config:        &c,
		ConsoleWriter: os.Stdout,
	}
	ctx := setup.Context{}
	err := s.Run(ctx)
	if err != nil {
		assert.Contains(t, err.Error(), "BEARER_TOKEN is not defined in environment")
	}
}

func TestUpdateServiceConfigSaveError(t *testing.T) {
	os.Setenv("SHVS_BASE_URL", "https://localhost")
	os.Setenv("SCS_BASE_URL", "https://localhost")
	os.Setenv("BEARER_TOKEN", RandStringBytes())
	c := config.Configuration{
		CMSBaseURL: "https://localhost",
	}

	s := Update_Service_Config{
		Flags:         []string{"-port=1337"},
		Config:        &c,
		ConsoleWriter: os.Stdout,
	}
	ctx := setup.Context{}
	err := s.Run(ctx)
	if err != nil {
		assert.Contains(t, err.Error(), "failed to save SGX Agent config")
	}
}

func TestUpdateServiceConfigPositiveCase(t *testing.T) {
	os.Setenv("SHVS_BASE_URL", "https://localhost")
	os.Setenv("SCS_BASE_URL", "https://localhost")
	os.Setenv("BEARER_TOKEN", RandStringBytes())

	c := *config.Load("testconfig.yml")
	defer os.Remove("testconfig.yml")

	s := Update_Service_Config{
		Flags:         []string{"-port=1337"},
		Config:        &c,
		ConsoleWriter: os.Stdout,
	}
	ctx := setup.Context{}
	err := s.Run(ctx)
	assert.NoError(t, err)
}

func TestUpdateLogLevelPositiveCase(t *testing.T) {
	os.Setenv("SGX_AGENT_LOGLEVEL", "INFO")

	c := *config.Load("testconfig.yml")
	defer os.Remove("testconfig.yml")

	s := Update_Service_Config{
		Flags:         []string{"-port=1337"},
		Config:        &c,
		ConsoleWriter: os.Stdout,
	}
	ctx := setup.Context{}
	err := s.Run(ctx)
	assert.NoError(t, err)
}

func TestUpdateSetEnableConsoleLogPositiveCase(t *testing.T) {
	os.Setenv("SGX_AGENT_ENABLE_CONSOLE_LOG", "true")

	c := *config.Load("testconfig.yml")
	defer os.Remove("testconfig.yml")

	s := Update_Service_Config{
		Flags:         []string{"-port=1337"},
		Config:        &c,
		ConsoleWriter: os.Stdout,
	}
	ctx := setup.Context{}
	err := s.Run(ctx)
	assert.NoError(t, err)
}

func TestUpdateServiceConfigValidate(t *testing.T) {

	c := *config.Load("testconfig.yml")
	defer os.Remove("testconfig.yml")

	s := Update_Service_Config{
		Flags:         []string{"-port=1337"},
		Config:        &c,
		ConsoleWriter: os.Stdout,
	}
	ctx := setup.Context{}
	err := s.Validate(ctx)
	assert.NoError(t, err)
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func RandStringBytes() string {
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, 10)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}
