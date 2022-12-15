/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package version

import "testing"

func TestGetVersion(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{
			name: "Positive Test",
			want: "Service Name: SGX Agent\nVersion: -\nBuild Date: \n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetVersion(); got != tt.want {
				t.Errorf("GetVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}
