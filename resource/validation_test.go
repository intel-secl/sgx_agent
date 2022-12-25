/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"intel/isecl/sgx_agent/v5/constants"
	"testing"
)

func TestValidateInputString(t *testing.T) {
	type args struct {
		key      string
		inString string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Positive test",
			args: args{key: constants.PceIDKey, inString: "7234"},
			want: true,
		},
		{
			name: "Negative test",
			args: args{key: "", inString: "7234"},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validateInputString(tt.args.key, tt.args.inString); got != tt.want {
				t.Errorf("validateInputString() = %v, want %v", got, tt.want)
			}
		})
	}
}
