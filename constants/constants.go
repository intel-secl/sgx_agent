/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

const (
	HomeDir         = "/opt/sgx_agent/"
	ConfigDir       = "/etc/sgx_agent/"
	ExecutableDir   = "/opt/sgx_agent/bin/"
	ExecLinkPath    = "/usr/bin/sgx_agent"
	RunDirPath      = "/run/sgx_agent"
	LogDir          = "/var/log/sgx_agent/"
	LogFile         = LogDir + "sgx_agent.log"
	SecurityLogFile = LogDir + "sgx_agent-security.log"
	HTTPLogFile     = LogDir + "http.log"
	ConfigFile      = "config.yml"

	TrustedCAsStoreDir               = ConfigDir + "certs/trustedca/"
	TLSCertPath                      = ConfigDir + "tls-cert.pem"
	TLSKeyPath                       = ConfigDir + "tls-key.pem"
	SerialNumberPath                 = ConfigDir + "serial-number"
	TokenSignKeysAndCertDir          = ConfigDir + "certs/tokensign/"
	TokenSignCertFile                = TokenSignKeysAndCertDir + "jwtsigncert.pem"
	TrustedJWTSigningCertsDir        = ConfigDir + "certs/trustedjwt/"
	TrustedCaCertsDir                = ConfigDir + "certs/trustedca"
	JWTCertsCacheTime                = "1m"
	PIDFile                          = "sgx_agent.pid"
	ServiceRemoveCmd                 = "systemctl disable sgx_agent"
	DefaultAuthDefendMaxAttempts     = 5
	DefaultAuthDefendIntervalMins    = 5
	DefaultAuthDefendLockoutMins     = 15
	ServiceName                      = "SGX_AGENT"
	DefaultTokenDurationMins         = 240
	DefaultHttpPort                  = 8445
	DefaultKeyAlgorithm              = "rsa"
	DefaultKeyAlgorithmLength        = 3072
	DefaultTlsSan                    = "127.0.0.1,localhost"
	DefaultSGX_AgentTlsCn            = "SGX_AGENT TLS Certificate"
	DefaultSGX_AgentJwtCn            = "SGX_AGENT JWT Signing Certificate"
	CertApproverGroupName            = "CertApprover"
	DefaultSGX_AgentCertProvince     = "SF"
	DefaultSGX_AgentCertLocality     = "SC"
	DefaultCACertValidiy             = 5
	DefaultRootCACommonName          = "SGX_AGENTCA"
	DefaultPort                      = 8445
	DefaultSGX_AgentCertOrganization = "INTEL"
	DefaultSGX_AgentCertCountry      = "US"
)

// State represents whether or not a daemon is running or not
type State bool

const (
	// Stopped is the default nil value, indicating not running
	Stopped State = false
	// Running means the daemon is active
	Running      State = true
	ProxyEnable        = true
	ProxyDisable       = false
)
