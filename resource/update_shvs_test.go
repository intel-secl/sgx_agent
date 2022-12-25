/*
* Copyright (C) 2022 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"intel/isecl/sgx_agent/v5/config"
	"testing"
)

func TestPushSGXEnablementData(t *testing.T) {
	sgxDiscoveryData := &SGXDiscoveryData{}
	type args struct {
		sgxDiscovery *SGXDiscoveryData
		hardwareUUID string
		tcbStatus    bool
		client       HttpClient
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "401 status code error",
			args: args{
				sgxDiscovery: sgxDiscoveryData,
			},
			wantErr: true,
		},
		{
			name: "Unmarshalling error",
			args: args{
				sgxDiscovery: sgxDiscoveryData,
			},
			wantErr: true,
		},
		{
			name: "Error in reading response body",
			args: args{
				sgxDiscovery: sgxDiscoveryData,
			},
			wantErr: true,
		},
		{
			name: "Http client error",
			args: args{
				sgxDiscovery: sgxDiscoveryData,
			},
			wantErr: true,
		},
		{
			name: "200 status code - push sgx enablement data successfully",
			args: args{
				sgxDiscovery: sgxDiscoveryData,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
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
		} else if tt.name == "Http client error" {
			tt.args.client = nil
		} else {
			tt.args.client = &ClientMock{}
		}
		if tt.name == "200 status code - push sgx enablement data successfully" || tt.name == "Error in reading response body" || tt.name == "401 status code error" ||
			tt.name == "Http client error" {
			config.GlobalConfig = &config.Configuration{
				BearerToken: generateJWT(),
			}
		} else {
			config.GlobalConfig = &config.Configuration{
				BearerToken: "test",
			}
		}
		t.Run(tt.name, func(t *testing.T) {
			if err := PushSGXEnablementData(tt.args.client, tt.args.sgxDiscovery, tt.args.hardwareUUID, tt.args.tcbStatus); (err != nil) != tt.wantErr {
				t.Errorf("PushSGXEnablementData() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
