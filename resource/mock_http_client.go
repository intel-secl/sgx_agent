/*
* Copyright (C) 2022 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/pkg/errors"
)

type errReader int

var RetryTimes int

func (errReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("test error")
}

func (errReader) Close() error {
	return nil
}

func (c *ClientMock) Do(req *http.Request) (*http.Response, error) {
	if c.FakeStatusCode == 401 {
		return &http.Response{StatusCode: 401, Body: ioutil.NopCloser(bytes.NewReader([]byte("test")))}, nil
	}

	if c.FakeStatusCode == 500 {
		if RetryTimes <= 1 {
			RetryTimes++
			return &http.Response{StatusCode: 500, Body: ioutil.NopCloser(bytes.NewReader([]byte("test")))}, nil
		} else {
			RetryTimes = 0
		}
	}

	if c.UnmarshallResponseError {
		body := []byte("'{\"test\":\"cnskc\", \"version\":v1,}'")
		return &http.Response{
			StatusCode: 200,
			Body:       ioutil.NopCloser(bytes.NewReader(body)),
		}, nil
	}

	if c.ResponseBodyError {
		return &http.Response{StatusCode: 200,
			Body: errReader(0)}, nil
	}

	header := make(http.Header)
	var respBody map[string]interface{}
	respBody = make(map[string]interface{})
	respBody["Status"] = "test"
	body, _ := json.Marshal(respBody)

	return &http.Response{StatusCode: 200,
		Body:   ioutil.NopCloser(bytes.NewReader(body)),
		Header: header}, nil
}
