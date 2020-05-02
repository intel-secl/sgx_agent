/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path"
	"strconv"
	"sync"
	"time"

	errorLog "github.com/pkg/errors"
	commLog "intel/isecl/lib/common/v2/log"
	"intel/isecl/lib/common/v2/setup"
	"intel/isecl/sgx_agent/constants"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

// Configuration is the global configuration struct that is marshalled/unmarshaled to a persisted yaml file
// Probably should embed a config generic struct
type Configuration struct {
	configFile       string
	Port             int
	CmsTlsCertDigest string
	LogMaxLength     int
	LogEnableStdout  bool
	LogLevel         log.Level

	KeyAlgorithm       string
	KeyAlgorithmLength int
	CACertValidity     int
	TokenDurationMins  int

	AuthDefender struct {
		MaxAttempts         int
		IntervalMins        int
		LockoutDurationMins int
	}

	SGX_AgentUserName string
	SGX_AgentPassword string
	CMSBaseUrl        string
	AuthServiceUrl    string
	SGXHVSBaseUrl     string
	SVSBaseURL        string
	Subject           struct {
		TLSCertCommonName string
	}
	TLSKeyFile        string
	TLSCertFile       string
	CertSANList       string
	ReadTimeout       time.Duration
	ReadHeaderTimeout time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	MaxHeaderBytes    int

	TrustedRootCA *x509.Certificate
	ProxyUrl      string
	ProxyEnable   string
}

var mu sync.Mutex
var global *Configuration

func Global() *Configuration {
	log.Trace("config/config:Global() Entering")
	defer log.Trace("config/config:Global() Leaving")

	if global == nil {
		global = Load(path.Join(constants.ConfigDir, constants.ConfigFile))
	}
	return global
}

var ErrNoConfigFile = errors.New("no config file")

func (conf *Configuration) SaveConfiguration(c setup.Context) error {
	log.Trace("config/config:SaveConfiguration() Entering")
	defer log.Trace("config/config:SaveConfiguration() Leaving")

	var err error = nil

	sgx_agentUserName, err := c.GetenvString("SGX_AGENT_USERNAME", "SGX_AGENT Username")
	if err == nil && sgx_agentUserName != "" {
		conf.SGX_AgentUserName = sgx_agentUserName
	} else if conf.SGX_AgentUserName == "" {
		log.Error("SGX_AGENT_USERNAME is not defined in environment")
	}

	sgx_agentPssword, err := c.GetenvString("SGX_AGENT_PASSWORD", "SGX_AGENT Password")
	if err == nil && sgx_agentPssword != "" {
		conf.SGX_AgentPassword = sgx_agentPssword
	} else if conf.SGX_AgentPassword == "" {
		log.Error("SGX_AGENT_PASSWORD is not defined in environment")
	}

	tlsCertDigest, err := c.GetenvString(constants.CmsTlsCertDigestEnv, "TLS certificate digest")
	if err == nil && tlsCertDigest != "" {
		conf.CmsTlsCertDigest = tlsCertDigest
	} else if conf.CmsTlsCertDigest == "" {
		commLog.GetDefaultLogger().Error("CMS_TLS_CERT_SHA384 is not defined in environment")
		return errorLog.Wrap(errors.New("CMS_TLS_CERT_SHA384 is not defined in environment"), "SaveConfiguration() ENV variable not found")
	}

	cmsBaseUrl, err := c.GetenvString("CMS_BASE_URL", "CMS Base URL")
	if err == nil && cmsBaseUrl != "" {
		conf.CMSBaseUrl = cmsBaseUrl
	} else if conf.CMSBaseUrl == "" {
		commLog.GetDefaultLogger().Error("CMS_BASE_URL is not defined in environment")
		return errorLog.Wrap(errors.New("CMS_BASE_URL is not defined in environment"), "SaveConfiguration() ENV variable not found")
	}

	aasApiUrl, err := c.GetenvString("AAS_API_URL", "AAS API URL")
	if err == nil && aasApiUrl != "" {
		conf.AuthServiceUrl = aasApiUrl
	} else if conf.AuthServiceUrl == "" {
		commLog.GetDefaultLogger().Error("AAS_API_URL is not defined in environment")
		return errorLog.Wrap(errors.New("AAS_API_URL is not defined in environment"), "SaveConfiguration() ENV variable not found")
	}

	sgxHVSBaseUrl, err := c.GetenvString("HVS_BASE_URL", "HVS Base URL")
	if err == nil && sgxHVSBaseUrl != "" {
		conf.SGXHVSBaseUrl = sgxHVSBaseUrl
	} else if conf.SGXHVSBaseUrl == "" {
		log.Error("HVS_BASE_URL is not defined in environment")
	}

	logLevel, err := c.GetenvString("SGX_AGENT_LOG_LEVEL", "SGX_AGENT Log Level")
	if err != nil {
		fmt.Fprintln(os.Stderr, "No logging level specified, using default logging level: Error")
		conf.LogLevel = log.ErrorLevel
	}
	conf.LogLevel, err = log.ParseLevel(logLevel)

	proxyUrl, err := c.GetenvString("PROXY_URL", "Enviroment Proxy URL")
	if err == nil && proxyUrl != "" {
		conf.ProxyUrl = proxyUrl
	} else if conf.ProxyUrl == "" {
		log.Error("PROXY_URL is not defined in environment")
	}

	setProxy, err := c.GetenvString("PROXY_ENABLE", "Set Proxy Enable/Disable")
	if err == nil && setProxy != "" {
		conf.ProxyEnable = setProxy
	} else if conf.ProxyEnable == "" {
		conf.ProxyEnable = strconv.FormatBool(constants.ProxyDisable)
	}

	tlsCertCN, err := c.GetenvString("SGX_AGENT_TLS_CERT_CN", "SGX_AGENT TLS Certificate Common Name")
	if err == nil && tlsCertCN != "" {
		conf.Subject.TLSCertCommonName = tlsCertCN
	} else if conf.Subject.TLSCertCommonName == "" {
		conf.Subject.TLSCertCommonName = constants.DefaultSGX_AgentTlsCn
	}

	tlsKeyPath, err := c.GetenvString("KEY_PATH", "Path of file where TLS key needs to be stored")
	if err == nil && tlsKeyPath != "" {
		conf.TLSKeyFile = tlsKeyPath
	} else if conf.TLSKeyFile == "" {
		conf.TLSKeyFile = constants.DefaultTLSKeyFile
	}

	tlsCertPath, err := c.GetenvString("CERT_PATH", "Path of file/directory where TLS certificate needs to be stored")
	if err == nil && tlsCertPath != "" {
		conf.TLSCertFile = tlsCertPath
	} else if conf.TLSCertFile == "" {
		conf.TLSCertFile = constants.DefaultTLSCertFile
	}

	sanList, err := c.GetenvString("SAN_LIST", "SAN list for TLS")
	if err == nil && sanList != "" {
		conf.CertSANList = sanList
	} else if conf.CertSANList == "" {
		conf.CertSANList = constants.DefaultTlsSan
	}

	log.Info("logLevel: ", conf.LogLevel)
	return conf.Save()
}

func (c *Configuration) Save() error {
	log.Trace("config/config:Save() Entering")
	defer log.Trace("config/config:Save() Leaving")

	if c.configFile == "" {
		return ErrNoConfigFile
	}
	file, err := os.OpenFile(c.configFile, os.O_RDWR, 0)
	if err != nil {
		// we have an error
		if os.IsNotExist(err) {
			// error is that the config doesnt yet exist, create it
			file, err = os.Create(c.configFile)
			os.Chmod(c.configFile, 0660)
			if err != nil {
				return err
			}
		} else {
			// someother I/O related error
			return err
		}
	}
	defer file.Close()
	return yaml.NewEncoder(file).Encode(c)
}

func Load(path string) *Configuration {
	log.Trace("config/config:Load() Entering")
	defer log.Trace("config/config:Load() Leaving")

	var c Configuration
	file, err := os.Open(path)
	if err == nil {
		defer file.Close()
		yaml.NewDecoder(file).Decode(&c)
	} else {
		// file doesnt exist, create a new blank one
		c.LogLevel = log.InfoLevel
	}

	c.configFile = path
	return &c
}
