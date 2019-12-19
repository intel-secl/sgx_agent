/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package utils

import (
	"os/exec"
	"strings"
)

func ReadAndParseFromCommandLine(input []string) ([]string, error) {
	cmd := exec.Command(input[0], input[1:]...)
	out, err := cmd.CombinedOutput()
	result := strings.Split(string(out), "\n")
	cleanedResult := deleteEmptyFromSlice(result)
	return cleanedResult, err
}

func deleteEmptyFromSlice(s []string) []string {
	r := make([]string, 0)
	for i := range s {
		trimmed := strings.TrimSpace(s[i])
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if trimmed != "" {
			r = append(r, trimmed)
		}
	}
	return r
}
