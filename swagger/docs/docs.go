// SGX Agent
//
// SGX Agent provides detailed resource information specific to Intel Software Guard Extensions (SGX) security technology
// which includes SGX Discovery, SGX Enablement Information, Flexible Launch control support and SGX EPC Memory
// Availability with size information. SGX Agent also collects the SGX platform-specific values, explicitly SGX Platform Manifest,
// Encrypted PPID, CPU SVN, ISV SVN, PCE ID and QEID on the SGX enabled platform. SGX Agent listening port is user-configurable.
//
//  License: Copyright (C) 2020 Intel Corporation. SPDX-License-Identifier: BSD-3-Clause
//
//  Version: 1.0
//  Host: sgx-agent.com:11001
//  BasePath: /sgx_agent/v1
//
//  Schemes: https
//
//  SecurityDefinitions:
//   bearerAuth:
//     type: apiKey
//     in: header
//     name: Authorization
//     description: Enter your bearer token in the format **Bearer &lt;token&gt;**
//
// swagger:meta
package docs
