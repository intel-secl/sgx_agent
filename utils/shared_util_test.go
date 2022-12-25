/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package utils

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func TestReadAndParseFromCommandLine(t *testing.T) {
	type args struct {
		input []string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			name:    "Positive test",
			args:    args{input: []string{"ls"}},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ReadAndParseFromCommandLine(tt.args.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadAndParseFromCommandLine() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestDeleteEmptyFromSlice(t *testing.T) {
	type args struct {
		s []string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "Positive test",
			args: args{s: []string{"hi", "", "#ok", "hi"}},
			want: []string{"hi", "hi"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := deleteEmptyFromSlice(tt.args.s); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("deleteEmptyFromSlice() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestJwtHasExpired(t *testing.T) {

	type args struct {
		tokenString string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name:    "Empty jwt token",
			args:    args{tokenString: ""},
			wantErr: true,
		},
		{
			name:    "Invalid jwt token",
			args:    args{tokenString: "yyyywwwa"},
			wantErr: true,
		},
		{
			name:    "Valid jwt token",
			args:    args{tokenString: generateExpiredJWT()},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := JwtHasExpired(tt.args.tokenString)
			if (err != nil) != tt.wantErr {
				t.Errorf("JwtHasExpired() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

var sampleSecretKey = []byte("GoLinuxCloudKey")

func generateExpiredJWT() string {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)

	claims["authorized"] = true

	claims["exp"] = time.Now()

	tokenString, err := token.SignedString(sampleSecretKey)

	if err != nil {
		fmt.Errorf("generateJWT(): %s", err.Error())
		return ""
	}
	return tokenString
}
