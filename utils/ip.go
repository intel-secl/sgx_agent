/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package utils

import (
	"errors"
	log "github.com/sirupsen/logrus"
	"net"
	"strings"
)

func GetLocalIpAsString() (string, error) {

	addr, err := getLocalIpAddr()
	if err != nil {
		return "", err
	}

	// trim "/24" from addr if present
	ipString := addr.String()

	idx := strings.Index(ipString, "/")
	if idx > -1 {
		ipString = ipString[:idx]
	}

	return ipString, nil
}

//
// This function attempts to create a byte array from the host's ip address.  This
// is used to create a sha1 digest of the nonce that will make HVS happpy.
//
func GetLocalIpAsBytes() ([]byte, error) {

	addr, err := getLocalIpAddr()
	if err != nil {
		return nil, err
	}

	if ipnet, ok := addr.(*net.IPNet); ok {
		return ipnet.IP[(len(ipnet.IP) - 4):len(ipnet.IP)], nil
	}

	return nil, errors.New("Could not collect local ip bytes")
}

func getLocalIpAddr() (net.Addr, error) {

	var addr net.Addr

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}

	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				if !strings.HasPrefix(ipnet.String(), "192.") {
					log.Debugf("Found local ip address %s", ipnet.String())
					addr = ipnet
					break
				}
			}
		}
	}

	if addr == nil {
		return nil, errors.New("Did not find the local ip address")
	}

	return addr, nil
}
