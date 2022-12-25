/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package resource

import (
	"intel/isecl/sgx_agent/v5/config"
	"intel/isecl/sgx_agent/v5/constants"
	"os"
	"reflect"
	"testing"
)

func TestIsPCKDataCached(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{
			name: "File does not exist",
			want: false,
		},
		{
			name: "File exists",
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "File does not exist" {
				readPCKDetailsFromCache()
			}
			if tt.name == "File exists" {
				writePCKData("test")
				readPCKDetailsFromCache()
			}
			if got := isPCKDataCached(); got != tt.want {
				t.Errorf("isPCKDataCached() = %v, want %v", got, tt.want)
			}
		})
		os.Remove(constants.PCKDataFile)
	}
}

func TestExtractSGXPlatformValues(t *testing.T) {
	tests := []struct {
		name                 string
		want                 *SGXDiscoveryData
		ExpectedPlatformData *PlatformData
		wantErr              bool
	}{
		{
			name:    "Test 1",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, platformData, err := ExtractSGXPlatformValues()
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractSGXPlatformValues() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ExtractSGXPlatformValues() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(platformData, tt.ExpectedPlatformData) {
				t.Errorf("ExtractSGXPlatformValues() platformData = %v, want %v", platformData, tt.ExpectedPlatformData)
			}
		})
	}
}

func TestEpcMemoryDetails(t *testing.T) {
	tests := []struct {
		name          string
		wantEpcOffset string
	}{
		{
			name:          "Test",
			wantEpcOffset: "0x00000000",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotEpcOffset, _ := epcMemoryDetails()
			if gotEpcOffset != tt.wantEpcOffset {
				t.Errorf("epcMemoryDetails() gotEpcOffset = %v, want %v", gotEpcOffset, tt.wantEpcOffset)
			}
		})
	}
}

func TestPushSGXData(t *testing.T) {
	platformData := &PlatformData{}
	type args struct {
		client       HttpClient
		pdata        *PlatformData
		hardwareUUID string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "401 status code error",
			args: args{
				pdata: platformData,
			},
			wantErr: true,
		},
		{
			name: "Unmarshalling error",
			args: args{
				pdata: platformData,
			},
			wantErr: true,
		},
		{
			name: "Error in reading response body",
			args: args{
				pdata: platformData,
			},
			wantErr: true,
		},
		{
			name: "Expired token",
			args: args{
				pdata: platformData,
			},
			wantErr: true,
		},
		{
			name: "Get tcb status successfully after retry",
			args: args{
				pdata: platformData,
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "200 status code - get tcb status successfully",
			args: args{
				pdata: platformData,
			},
			want:    true,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		if tt.name == "401 status code error" {
			tt.args.client = &ClientMock{
				FakeStatusCode: 401,
			}
		} else if tt.name == "Get tcb status successfully after retry" {
			tt.args.client = &ClientMock{
				FakeStatusCode: 500,
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

		if tt.name == "200 status code - get tcb status successfully" || tt.name == "Get tcb status successfully after retry" || tt.name == "401 status code error" {
			config.GlobalConfig = &config.Configuration{
				BearerToken: generateJWT(),
			}
		} else {
			config.GlobalConfig = &config.Configuration{
				BearerToken: "test",
			}
		}
		t.Run(tt.name, func(t *testing.T) {
			got, err := PushSGXData(tt.args.client, tt.args.pdata, tt.args.hardwareUUID)
			if (err != nil) != tt.wantErr {
				t.Errorf("PushSGXData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("PushSGXData() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReadMSR(t *testing.T) {
	currentDir, _ := os.Getwd()
	type args struct {
		offset int64
		path   string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "No such file or directory error",
			args: args{
				offset: 0,
				path:   currentDir + "/test/error.txt",
			},
			wantErr: true,
		},
		{
			name: "Invalid offset error",
			args: args{
				offset: 100,
				path:   currentDir + "/test/text.txt",
			},
			wantErr: true,
		},
		{
			name: "Read sample MSR file successfully",
			args: args{
				offset: 0,
				path:   currentDir + "/test/text.txt",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ReadMSR(tt.args.offset, tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadMSR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestIsSGXAndFLCEnabled(t *testing.T) {
	currentDir, _ := os.Getwd()
	type args struct {
		featureControlRegister int64
		msrDevicePath          string
	}
	tests := []struct {
		name           string
		args           args
		wantSgxEnabled bool
		wantFlcEnabled bool
		wantErr        bool
	}{
		{
			name: "Error in reading msr",
			args: args{
				featureControlRegister: 0,
				msrDevicePath:          currentDir + "/test/error.txt",
			},
			wantSgxEnabled: false,
			wantFlcEnabled: false,
			wantErr:        true,
		},
		{
			name: "Sample test file sgxEnabled false and flcEnabled false",
			args: args{
				featureControlRegister: 0,
				msrDevicePath:          currentDir + "/test/text.txt",
			},
			wantSgxEnabled: false,
			wantFlcEnabled: false,
			wantErr:        false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSgxEnabled, gotFlcEnabled, err := isSGXAndFLCEnabled(tt.args.featureControlRegister, tt.args.msrDevicePath)
			if (err != nil) != tt.wantErr {
				t.Errorf("isSGXAndFLCEnabled() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotSgxEnabled != tt.wantSgxEnabled {
				t.Errorf("isSGXAndFLCEnabled() gotSgxEnabled = %v, want %v", gotSgxEnabled, tt.wantSgxEnabled)
			}
			if gotFlcEnabled != tt.wantFlcEnabled {
				t.Errorf("isSGXAndFLCEnabled() gotFlcEnabled = %v, want %v", gotFlcEnabled, tt.wantFlcEnabled)
			}
		})
	}
}
