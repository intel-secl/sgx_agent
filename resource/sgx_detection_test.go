/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package resource

import (
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetSgxQuoteWithoutHeader(t *testing.T) {
	input := TestData{
		Recorder:   httptest.NewRecorder(),
		Assert:     assert.New(t),
		Router:     setupRouter(t),
		Test:       t,
		Url:        "/sgx_agent/v1/host",
		StatusCode: http.StatusNotAcceptable,
	}
	req := httptest.NewRequest("GET", input.Url, nil)
	input.Router.ServeHTTP(input.Recorder, req)
	input.Assert.Equal(input.StatusCode, input.Recorder.Code)
	input.Test.Log("Test:", input.Description, ", Response:", input.Recorder.Body)
	input.Test.Log("Test:", input.Description, " ended")
}

func TestSgxQuotePushInvalidData(t *testing.T) {
	input := TestData{
		Recorder:   httptest.NewRecorder(),
		Assert:     assert.New(t),
		Router:     setupRouter(t),
		Test:       t,
		Url:        "/sgx_agent/v1/host",
		StatusCode: http.StatusOK,
	}
	req := httptest.NewRequest("GET", input.Url, nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")
	input.Router.ServeHTTP(input.Recorder, req)
	input.Assert.Equal(input.StatusCode, input.Recorder.Code)
	input.Test.Log("Test:", input.Description, ", Response:", input.Recorder.Body)
	input.Test.Log("Test:", input.Description, " ended")

}
