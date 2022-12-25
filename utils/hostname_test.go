/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package utils

import "testing"

func TestGetLocalHostname(t *testing.T) {
	tests := []struct {
		name    string
		want    string
		wantErr bool
	}{
		{
			name:    "Positive test",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetLocalHostname()
			if (err != nil) != tt.wantErr {
				t.Errorf("GetLocalHostname() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
