/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"intel/isecl/lib/common/v3/crypt"
	e "intel/isecl/lib/common/v3/exec"
	"intel/isecl/lib/common/v3/setup"
	"intel/isecl/lib/common/v3/validation"
	"intel/isecl/sgx_agent/v3/config"
	"intel/isecl/sgx_agent/v3/constants"
	"intel/isecl/sgx_agent/v3/resource"
	"intel/isecl/sgx_agent/v3/version"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"strconv"

	"strings"
	"syscall"
	"time"

	"github.com/pkg/errors"

	commLog "intel/isecl/lib/common/v3/log"
	commLogMsg "intel/isecl/lib/common/v3/log/message"
	commLogInt "intel/isecl/lib/common/v3/log/setup"
	cos "intel/isecl/lib/common/v3/os"
)

var log = commLog.GetDefaultLogger()
var slog = commLog.GetSecurityLogger()

type App struct {
	HomeDir        string
	ConfigDir      string
	LogDir         string
	ExecutablePath string
	ExecLinkPath   string
	RunDirPath     string
	Config         *config.Configuration
	ConsoleWriter  io.Writer
	LogWriter      io.Writer
	HTTPLogWriter  io.Writer
	SecLogWriter   io.Writer
}

func (a *App) printUsage() {
	w := a.consoleWriter()
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "    sgx_agent <command> [arguments]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Avaliable Commands:")
	fmt.Fprintln(w, "    help|-h|--help        Show this help message")
	fmt.Fprintln(w, "    setup [task]          Run setup task")
	fmt.Fprintln(w, "    start                 Start sgx_agent")
	fmt.Fprintln(w, "    status                Show the status of sgx_agent")
	fmt.Fprintln(w, "    stop                  Stop sgx_agent")
	fmt.Fprintln(w, "    uninstall             Uninstall sgx_agent")
	fmt.Fprintln(w, "    version|--version|-v  Show the version of sgx_agent")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Avaliable Tasks for setup:")
	fmt.Fprintln(w, "    all                       Runs all setup tasks")
	fmt.Fprintln(w, "                              Required env variables:")
	fmt.Fprintln(w, "                                  - get required env variables from all the setup tasks")
	fmt.Fprintln(w, "                              Optional env variables:")
	fmt.Fprintln(w, "                                  - get optional env variables from all the setup tasks")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "    download_ca_cert      Download CMS root CA certificate")
	fmt.Fprintln(w, "                          - Option [--force] overwrites any existing files, and always downloads new root CA cert")
	fmt.Fprintln(w, "                          Required env variables specific to setup task are:")
	fmt.Fprintln(w, "                              - CMS_BASE_URL=<url>                                : for CMS API url")
	fmt.Fprintln(w, "                              - CMS_TLS_CERT_SHA384=<CMS TLS cert sha384 hash>    : to ensure that SGX-Agent is talking to the right CMS instance")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "    download_cert TLS     Generates Key pair and CSR, gets it signed from CMS")
	fmt.Fprintln(w, "                          - Option [--force] overwrites any existing files, and always downloads newly signed TLS cert")
	fmt.Fprintln(w, "                          Required env variable if SGX_AGENT_NOSETUP=true or variable not set in config.yml:")
	fmt.Fprintln(w, "                              - CMS_TLS_CERT_SHA384=<CMS TLS cert sha384 hash>      : to ensure that SGX-Agent is talking to the right CMS instance")
	fmt.Fprintln(w, "                          Required env variables specific to setup task are:")
	fmt.Fprintln(w, "                              - CMS_BASE_URL=<url>               : for CMS API url")
	fmt.Fprintln(w, "                              - BEARER_TOKEN=<token>             : for authenticating with CMS")
	fmt.Fprintln(w, "                              - SAN_LIST=<san>                   : list of hosts which needs access to service")
	fmt.Fprintln(w, "                          Optional env variables specific to setup task are:")
	fmt.Fprintln(w, "                              - KEY_PATH=<key_path>              : Path of file where TLS key needs to be stored")
	fmt.Fprintln(w, "                              - CERT_PATH=<cert_path>            : Path of file/directory where TLS certificate needs to be stored")
	fmt.Fprintln(w, "")
}

func (a *App) consoleWriter() io.Writer {
	if a.ConsoleWriter != nil {
		return a.ConsoleWriter
	}
	return os.Stdout
}

func (a *App) logWriter() io.Writer {
	if a.LogWriter != nil {
		return a.LogWriter
	}
	return os.Stderr
}

func (a *App) httpLogWriter() io.Writer {
	if a.HTTPLogWriter != nil {
		return a.HTTPLogWriter
	}
	return os.Stderr
}

func (a *App) configuration() *config.Configuration {
	if a.Config != nil {
		return a.Config
	}
	return config.Global()
}

func (a *App) executablePath() string {
	if a.ExecutablePath != "" {
		return a.ExecutablePath
	}
	exec, err := os.Executable()
	if err != nil {
		log.WithError(err).Error("app:executablePath() Unable to find SGX_AGENT executable")
		// if we can't find self-executable path, we're probably in a state that is panic() worthy
		panic(err)
	}
	return exec
}

func (a *App) homeDir() string {
	if a.HomeDir != "" {
		return a.HomeDir
	}
	return constants.HomeDir
}

func (a *App) configDir() string {
	if a.ConfigDir != "" {
		return a.ConfigDir
	}
	return constants.ConfigDir
}

func (a *App) logDir() string {
	if a.LogDir != "" {
		return a.ConfigDir
	}
	return constants.LogDir
}

func (a *App) execLinkPath() string {
	if a.ExecLinkPath != "" {
		return a.ExecLinkPath
	}
	return constants.ExecLinkPath
}

func (a *App) runDirPath() string {
	if a.RunDirPath != "" {
		return a.RunDirPath
	}
	return constants.RunDirPath
}

func (a *App) configureLogs(stdOut, logFile bool) {

	var ioWriterDefault io.Writer
	ioWriterDefault = a.LogWriter

	if stdOut {
		if logFile {
			ioWriterDefault = io.MultiWriter(os.Stdout, a.LogWriter)
		} else {
			ioWriterDefault = os.Stdout
		}
	}

	ioWriterSecurity := io.MultiWriter(ioWriterDefault, a.SecLogWriter)
	f := commLog.LogFormatter{MaxLength: a.configuration().LogMaxLength}
	commLogInt.SetLogger(commLog.DefaultLoggerName, a.configuration().LogLevel, &f, ioWriterDefault, false)
	commLogInt.SetLogger(commLog.SecurityLoggerName, a.configuration().LogLevel, &f, ioWriterSecurity, false)

	slog.Info(commLogMsg.LogInit)
	log.Info(commLogMsg.LogInit)
}

func (a *App) Run(args []string) error {
	if len(args) < 2 {
		a.printUsage()
		os.Exit(1)
	}

	cmd := args[1]
	switch cmd {
	default:
		a.printUsage()
		fmt.Fprintf(os.Stderr, "Unrecognized command: %s\n", args[1])
		os.Exit(1)
	case "run":
		a.configureLogs(a.configuration().LogEnableStdout, true)
		if err := a.startAgent(); err != nil {
			fmt.Fprintln(os.Stderr, "Error: daemon did not start - ", err.Error())
			// wait some time for logs to flush - otherwise, there will be no entry in syslog
			time.Sleep(5 * time.Millisecond)
			return errors.Wrap(err, "app:Run() Error starting SGX Agent service")
		}
	case "help", "-h", "--help":
		a.printUsage()
		return nil
	case "start":
		a.configureLogs(a.configuration().LogEnableStdout, true)
		return a.start()
	case "stop":
		a.configureLogs(a.configuration().LogEnableStdout, true)
		return a.stop()
	case "status":
		a.configureLogs(a.configuration().LogEnableStdout, true)
		return a.status()
	case "uninstall":
		var purge bool
		flag.CommandLine.BoolVar(&purge, "purge", false, "purge config when uninstalling")
		err := flag.CommandLine.Parse(args[2:])
		if err != nil {
			return err
		}
		a.uninstall(purge)
		log.Info("app:Run() Uninstalled SGX Agent Service")
		os.Exit(0)
	case "version", "--version", "-v":
		fmt.Fprintf(a.consoleWriter(), "SGX Agent Service %s-%s\nBuilt %s\n", version.Version, version.GitHash, version.BuildDate)
	case "setup":
		a.configureLogs(a.configuration().LogEnableStdout, true)
		var context setup.Context
		if len(args) <= 2 {
			a.printUsage()
			log.Error("app:Run() Invalid command")
			os.Exit(1)
		}
		if args[2] != "download_ca_cert" &&
			args[2] != "download_cert" &&
			args[2] != "server" &&
			args[2] != "all" {
			a.printUsage()
			return errors.New("No such setup task")
		}
		valid_err := validateSetupArgs(args[2], args[3:])
		if valid_err != nil {
			return errors.Wrap(valid_err, "app:Run() Invalid setup task arguments")
		}
		a.Config = config.Global()
		err := a.Config.SaveConfiguration(context)
		if err != nil {
			fmt.Println("Error saving configuration: " + err.Error())
			os.Exit(1)
		}
		task := strings.ToLower(args[2])

		setupRunner := &setup.Runner{
			Tasks: []setup.Task{
				setup.Download_Ca_Cert{
					Flags:                args,
					CmsBaseURL:           a.Config.CMSBaseUrl,
					CaCertDirPath:        constants.TrustedCAsStoreDir,
					TrustedTlsCertDigest: a.Config.CmsTlsCertDigest,
					ConsoleWriter:        os.Stdout,
				},
				setup.Download_Cert{
					Flags:              args,
					CmsBaseURL:         a.Config.CMSBaseUrl,
					KeyFile:            a.Config.TLSKeyFile,
					CertFile:           a.Config.TLSCertFile,
					KeyAlgorithm:       constants.DefaultKeyAlgorithm,
					KeyAlgorithmLength: constants.DefaultKeyAlgorithmLength,
					Subject: pkix.Name{
						CommonName: a.Config.Subject.TLSCertCommonName,
					},
					SanList:       a.Config.CertSANList,
					CertType:      "TLS",
					CaCertsDir:    constants.TrustedCAsStoreDir,
					BearerToken:   "",
					ConsoleWriter: os.Stdout,
				},
			},
			AskInput: false,
		}

		if task == "all" {
			err = setupRunner.RunTasks()
		} else {
			err = setupRunner.RunTasks(task)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error running setup: %s\n", err)
			return err
		}

		sgxAgentUser, err := user.Lookup(constants.SGXAgentUserName)
		if err != nil {
			return errors.Wrapf(err, "Could not find user '%s'", constants.SGXAgentUserName)
		}

		uid, err := strconv.Atoi(sgxAgentUser.Uid)
		if err != nil {
			return errors.Wrapf(err, "Could not parse sgx-agent user uid '%s'", sgxAgentUser.Uid)
		}

		gid, err := strconv.Atoi(sgxAgentUser.Gid)
		if err != nil {
			return errors.Wrapf(err, "Could not parse sgx-agent user gid '%s'", sgxAgentUser.Gid)
		}

		//Change the file ownership to sgx-agent user

		err = cos.ChownR(constants.ConfigDir, uid, gid)
		if err != nil {
			return errors.Wrap(err, "Error while changing file ownership")
		}
		if task == "download_cert" {
			err = os.Chown(a.Config.TLSKeyFile, uid, gid)
			if err != nil {
				return errors.Wrap(err, "Error while changing ownership of TLS Key file")
			}

			err = os.Chown(a.Config.TLSCertFile, uid, gid)
			if err != nil {
				return errors.Wrap(err, "Error while changing ownership of TLS Cert file")
			}
		}
	}
	return nil
}

func (a *App) startAgent() error {
	log.Trace("app:startAgent() Entering")
	defer log.Trace("app:startAgent() Leaving")

	log.Info("Starting SGX Agent...")

	c := a.configuration()

	err, sgxDiscoveryData, platformData := resource.ExtractSGXPlatformValues()
	if err != nil {
		log.WithError(err).Error("Unable to extract SGX Platform Values. Terminating...")
		return err
	}

	//Check if SGX Supported && SGX Enabled && FLC Enabled.
	if sgxDiscoveryData.Sgx_supported != true {
		err := errors.New("SGX is not supported.")
		log.WithError(err).Error("SGX is not supported. Terminating...")
		return err
	}

	log.Debug("SGX is supported.")

	if sgxDiscoveryData.Sgx_enabled != true {
		err := errors.New("SGX is not enabled.")
		log.WithError(err).Error("SGX is not enabled. Terminating...")
		return err
	}
	log.Debug("SGX is enabled.")
	if sgxDiscoveryData.Flc_enabled != true {
		err := errors.New("FLC is not enabled.")
		log.WithError(err).Error("FLC is not enabled. Terminating...")
		return err
	}
	log.Debug("FLC is enabled.")
	status, err := resource.PushSGXData(platformData)
	if status != true && err != nil {
		log.WithError(err).Error("Unable to push platform data to SCS. Terminating...")
		return err
	}

	//If SHVS URL is configured, get the tcbstatus from SCS and Push to SHVS periodically
	if c.SGXHVSBaseUrl != "" {
		log.Info("SHVS URL is configured...")
		log.Debug("SHVS Update Interval is : ", c.SHVSUpdateInterval)

		//Start SHVS Update Beacon
		err = resource.UpdateSHVSPeriodically(sgxDiscoveryData, platformData, c.SHVSUpdateInterval)

		if err != nil {
			log.WithError(err).Error("Unable to update SHVS. Terminating...")
			return err
		}
	}
	slog.Info(commLogMsg.ServiceStop)
	return nil
}

func (a *App) start() error {
	log.Trace("app:start() Entering")
	defer log.Trace("app:start() Leaving")

	fmt.Fprintln(a.consoleWriter(), `Forwarding to "systemctl start sgx_agent"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return err
	}
	return syscall.Exec(systemctl, []string{"systemctl", "start", "sgx_agent"}, os.Environ())
}

func (a *App) stop() error {
	log.Trace("app:stop() Entering")
	defer log.Trace("app:stop() Leaving")

	fmt.Fprintln(a.consoleWriter(), `Forwarding to "systemctl stop sgx_agent"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return err
	}
	return syscall.Exec(systemctl, []string{"systemctl", "stop", "sgx_agent"}, os.Environ())
}

func (a *App) status() error {
	log.Trace("app:status() Entering")
	defer log.Trace("app:status() Leaving")

	fmt.Fprintln(a.consoleWriter(), `Forwarding to "systemctl status sgx_agent"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return err
	}
	return syscall.Exec(systemctl, []string{"systemctl", "status", "sgx_agent"}, os.Environ())
}

func (a *App) uninstall(purge bool) {
	log.Trace("app:uninstall() Entering")
	defer log.Trace("app:uninstall() Leaving")

	fmt.Println("Uninstalling SGX Service")
	removeService()

	fmt.Println("removing : ", a.executablePath())
	err := os.Remove(a.executablePath())
	if err != nil {
		log.WithError(err).Error("error removing executable")
	}

	fmt.Println("removing : ", a.runDirPath())
	err = os.Remove(a.runDirPath())
	if err != nil {
		log.WithError(err).Error("error removing ", a.runDirPath())
	}
	fmt.Println("removing : ", a.execLinkPath())
	err = os.Remove(a.execLinkPath())
	if err != nil {
		log.WithError(err).Error("error removing ", a.execLinkPath())
	}

	if purge {
		fmt.Println("removing : ", a.configDir())
		err = os.RemoveAll(a.configDir())
		if err != nil {
			log.WithError(err).Error("error removing config dir")
		}
	}
	fmt.Println("removing : ", a.logDir())
	err = os.RemoveAll(a.logDir())
	if err != nil {
		log.WithError(err).Error("error removing log dir")
	}
	fmt.Println("removing : ", a.homeDir())
	err = os.RemoveAll(a.homeDir())
	if err != nil {
		log.WithError(err).Error("error removing home dir")
	}
	fmt.Fprintln(a.consoleWriter(), "SGX Agent Service uninstalled")
	err = a.stop()
	if err != nil {
		log.WithError(err).Error("error stopping service")
	}
}
func removeService() {
	log.Trace("app:removeService() Entering")
	defer log.Trace("app:removeService() Leaving")

	_, _, err := e.RunCommandWithTimeout(constants.ServiceRemoveCmd, 5)
	if err != nil {
		fmt.Println("Could not remove SGX Agent Service")
		fmt.Println("Error : ", err)
	}
}

func validateCmdAndEnv(env_names_cmd_opts map[string]string, flags *flag.FlagSet) error {
	log.Trace("app:validateCmdAndEnv() Entering")
	defer log.Trace("app:validateCmdAndEnv() Leaving")

	env_names := make([]string, 0)
	for k := range env_names_cmd_opts {
		env_names = append(env_names, k)
	}

	missing, err := validation.ValidateEnvList(env_names)
	if err != nil && missing != nil {
		for _, m := range missing {
			if cmd_f := flags.Lookup(env_names_cmd_opts[m]); cmd_f == nil {
				return errors.New("app:validateCmdAndEnv() Insufficient arguments")
			}
		}
	}
	return nil
}

func validateSetupArgs(cmd string, args []string) error {
	log.Trace("app:validateSetupArgs() Entering")
	defer log.Trace("app:validateSetupArgs() Leaving")

	switch cmd {
	default:
		return errors.New("Unknown command")

	case "download_ca_cert":
		return nil

	case "download_cert":
		return nil

	case "server":
		return nil

	case "all":
		if len(args) != 0 {
			return errors.New("app:validateCmdAndEnv() Please setup the arguments with env")
		}
	}
	return nil
}

func fnGetJwtCerts() error {
	log.Trace("resource/service:fnGetJwtCerts() Entering")
	defer log.Trace("resource/service:fnGetJwtCerts() Leaving")

	conf := config.Global()

	if !strings.HasSuffix(conf.AuthServiceUrl, "/") {
		conf.AuthServiceUrl = conf.AuthServiceUrl + "/"
	}
	url := conf.AuthServiceUrl + "noauth/jwt-certificates"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return errors.Wrap(err, "Could not create http request")
	}
	req.Header.Add("accept", "application/x-pem-file")
	rootCaCertPems, err := cos.GetDirFileContents(constants.TrustedCAsStoreDir, "*.pem")
	if err != nil {
		return errors.Wrap(err, "Could not read root CA certificate")
	}

	// Get the SystemCertPool, continue with an empty pool on error
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	for _, rootCACert := range rootCaCertPems {
		if ok := rootCAs.AppendCertsFromPEM(rootCACert); !ok {
			return err
		}
	}
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
				RootCAs:            rootCAs,
			},
		},
	}

	res, err := httpClient.Do(req)
	if res != nil {
		defer func() {
			derr := res.Body.Close()
			if derr != nil {
				log.WithError(derr).Error("Error closing response")
			}
		}()
	}

	if err != nil {
		return errors.Wrap(err, "Could not retrieve jwt certificate")
	}

	body, _ := ioutil.ReadAll(res.Body)
	err = crypt.SavePemCertWithShortSha1FileName(body, constants.TrustedJWTSigningCertsDir)
	if err != nil {
		return errors.Wrap(err, "Could not store Certificate")
	}
	return nil
}
