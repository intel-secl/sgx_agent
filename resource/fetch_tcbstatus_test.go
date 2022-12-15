/*
* Copyright (C) 2022 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"fmt"
	"intel/isecl/sgx_agent/v5/config"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func TestGetTCBStatus(t *testing.T) {
	type args struct {
		qeID   string
		pceID  string
		client *ClientMock
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name:    "Token empty error",
			wantErr: true,
		},
		{
			name:    "TCB Status with valid token - http error",
			wantErr: true,
		},
		{
			name:    "401 status code error",
			wantErr: true,
		},
		{
			name:    "Unmarshalling error",
			wantErr: true,
		},
		{
			name:    "Error in reading response body",
			wantErr: true,
		},
		{
			name:    "200 status code - get tcb status successfully",
			wantErr: false,
			want:    "test",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name != "Token empty error" {
				config.GlobalConfig = &config.Configuration{
					BearerToken: generateJWT(),
				}
			}
			if tt.name == "401 status code error" {
				tt.args.client = &ClientMock{
					FakeStatusCode: 401,
				}
			} else if tt.name == "Unmarshalling error" {
				tt.args.client = &ClientMock{
					UnmarshallResponseError: true,
				}
			} else if tt.name == "Error in reading response body" {
				tt.args.client = &ClientMock{
					ResponseBodyError: true,
				}
			} else {
				tt.args.client = &ClientMock{}
			}
			var got string
			var err error
			if tt.name != "TCB Status with valid token - http error" {
				got, err = GetTCBStatus(tt.args.client, tt.args.qeID, tt.args.pceID)
				if (err != nil) != tt.wantErr {
					t.Errorf("GetTCBStatus() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
			} else {
				got, err = GetTCBStatus(nil, tt.args.qeID, tt.args.pceID)
				if (err != nil) != tt.wantErr {
					t.Errorf("GetTCBStatus() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
			}
			if got != tt.want {
				t.Errorf("GetTCBStatus() = %v, want %v", got, tt.want)
			}
		})
	}
}

var sampleSecretKey = []byte("GoLinuxCloudKey")

func generateJWT() string {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)

	claims["authorized"] = true
	claims["exp"] = time.Now().Add(time.Minute * 30).Unix()

	tokenString, err := token.SignedString(sampleSecretKey)

	if err != nil {
		fmt.Errorf("generateJWT(): %s", err.Error())
		return ""
	}
	return tokenString
}
