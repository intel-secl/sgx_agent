/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package utils

import (
	"fmt"
	"intel/isecl/sgx_agent/config"
)

func GetConnectionString(cfg *config.Configuration) (string, error) {

	ip, err := GetLocalIpAsString()
	if err != nil {
		return "", err
	}

	connectionString := fmt.Sprintf("https://%s:%d/sgx_agent/v1", ip, cfg.Port)
	return connectionString, nil
}
