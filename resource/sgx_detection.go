/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package resource

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/klauspost/cpuid"
	"github.com/pkg/errors"
	"intel/isecl/lib/clients/v3"
	clog "intel/isecl/lib/common/v3/log"
	"intel/isecl/sgx_agent/v3/config"
	"intel/isecl/sgx_agent/v3/constants"
	"intel/isecl/sgx_agent/v3/utils"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// MSR.IA32_Feature_Control register tells availability of SGX
const (
	FeatureControlRegister = 0x3A
	MSRDevice              = "/dev/cpu/0/msr"
)

var log = clog.GetDefaultLogger()
var slog = clog.GetSecurityLogger()

type SGXDiscoveryData struct {
	SgxSupported        bool   `json:"sgx-supported"`
	SgxEnabled          bool   `json:"sgx-enabled"`
	FlcEnabled          bool   `json:"flc-enabled"`
	EpcStartAddress     string `json:"epc-offset"`
	EpcSize             string `json:"epc-size"`
	sgxInstructionSet   int
	maxEnclaveSizeNot64 int64
	maxEnclaveSize64    int64
}

type PlatformData struct {
	EncryptedPPID string `json:"enc-ppid"`
	PceID         string `json:"pceid"`
	CPUSvn        string `json:"cpusvn"`
	PceSvn        string `json:"pcesvn"`
	QeID          string `json:"qeid"`
	Manifest      string `json:"Manifest"`
}

var (
	pckIDRetrievalInfo = []string{"PCKIDRetrievalTool", "-f", "/opt/pckData"}
)

type SCSPushResponse struct {
	Status  string `json:"Status"`
	Message string `json:"Message"`
}

var sgxData SGXDiscoveryData
var platformData PlatformData

func ExtractSGXPlatformValues() (*SGXDiscoveryData, *PlatformData, error) {
	var sgxEnablementInfo *SGXDiscoveryData
	var sgxPlatformData *PlatformData

	sgxExtensionsEnabled := isCPUSupportsSGXExtensions()
	if !sgxExtensionsEnabled {
		log.Info("SGX Extensions aren't enabled. Not proceeding.")
		return nil, nil, nil
	}
	log.Info("SGX Extensions are enabled, hence proceeding further")
	sgxData.SgxSupported = sgxExtensionsEnabled
	sgxEnabled, flcEnabled, err := isSGXAndFLCEnabled()
	if err != nil {
		return nil, nil, errors.Wrap(err, "Error while checking SGX and FLC are enabled in MSR")
	}
	sgxData.SgxEnabled = sgxEnabled
	sgxData.FlcEnabled = flcEnabled

	epcStartAddress, epcSize := epcMemoryDetails()
	sgxData.EpcStartAddress = epcStartAddress
	sgxData.EpcSize = epcSize
	sgxInstructionSet := isSGXInstructionSetSuported()
	sgxData.sgxInstructionSet = sgxInstructionSet
	var maxEnclaveSizeNot64Val, maxEnclaveSize64Val = maxEnclaveSize()
	sgxData.maxEnclaveSizeNot64 = maxEnclaveSizeNot64Val
	sgxData.maxEnclaveSize64 = maxEnclaveSize64Val

	log.Debug("**********************************SGX SPECIFIC VALUES*****************************")
	log.Debug("sgx supported: ", sgxExtensionsEnabled)
	log.Debug("sgx enabled: ", sgxEnabled)
	log.Debug("flc enabled: ", flcEnabled)
	log.Debug("Start Address: ", epcStartAddress)
	log.Debug("Size: ", epcSize)
	log.Debug("SGXLevel Supported: ", sgxInstructionSet)
	log.Debug("Enclave size when CPU is not in 64 bit mode: ", maxEnclaveSizeNot64Val)
	log.Debug("Enclave size when CPU is in 64 bit mode: ", maxEnclaveSize64Val)

	sgxEnablementInfo = &sgxData

	if sgxEnabled && flcEnabled {
		log.Info("sgx and flc is enabled. Hence running PCKIDRetrieval tool")
		fileContents, err := writePCKDetails()
		if err == nil {
			// Parse the string as retrieved.
			s := strings.Split(fileContents, ",")
			log.Debug("EncryptedPPID: ", s[0])
			log.Debug("PCE_ID: ", s[1])
			log.Debug("CPUSVN: ", s[2])
			log.Debug("PCE ISVSVN: ", s[3])
			log.Debug("QE_ID: ", s[4])

			platformData.EncryptedPPID = s[0]
			platformData.PceID = s[1]
			platformData.CPUSvn = s[2]
			platformData.PceSvn = s[3]
			platformData.QeID = s[4]
			if len(s) > 5 {
				log.Debug("Manifest exists. This is a multi-package platform")
				platformData.Manifest = s[5]
			}
			// FIXME : Remove global var usage. Instead let the function return sgxPlatformData
			// and sgxEnablementInfo. This would make unit testing easier.
			sgxPlatformData = &platformData
		} else {
			log.WithError(err).Info("fileContents not retrieved from PCKIDRetrivalTool")
			return nil, nil, err
		}
	} else {
		log.Info("sgx and flc are not enabled. Hence not running PCKIDRetrieval tool")
		err := errors.New("unsupported")
		return nil, nil, err
	}
	return sgxEnablementInfo, sgxPlatformData, nil
}

// ReadMSR is a utility function that reads an 64 bit value from /dev/cpu/0/msr at offset 'offset'
func ReadMSR(offset int64) (uint64, error) {

	msr, err := os.Open(MSRDevice)
	if err != nil {
		return 0, errors.Wrapf(err, "sgx_detection:ReadMSR(): Error opening msr")
	}

	_, err = msr.Seek(offset, 0)
	if err != nil {
		return 0, errors.Wrapf(err, "sgx_detection:ReadMSR(): Could not seek to location %x", offset)
	}

	results := make([]byte, 8)
	readLen, err := msr.Read(results)
	if err != nil {
		return 0, errors.Wrapf(err, "sgx_detection:ReadMSR(): There was an error reading msr at offset %x", offset)
	}
	if readLen < 8 {
		return 0, errors.New("sgx_detection:ReadMSR(): Reading the msr returned the incorrect length")
	}

	err = msr.Close()
	if err != nil {
		return 0, errors.Wrapf(err, "sgx_detection:ReadMSR(): Error while closing msr device file")
	}
	return binary.LittleEndian.Uint64(results), nil
}

func isSGXAndFLCEnabled() (sgxEnabled, flcEnabled bool, err error) {
	sgxEnabled = false
	flcEnabled = false
	sgxBits, err := ReadMSR(FeatureControlRegister)
	if err != nil {
		return sgxEnabled, flcEnabled, errors.Wrap(err, "Error while reading MSR")
	}

	// check if SGX is enabled or not
	if (sgxBits&(1<<18) != 0) && (sgxBits&(1<<0) != 0) {
		sgxEnabled = true
	}

	// check if FLC is enabled or not
	if (sgxBits&(1<<17) != 0) && (sgxBits&(1<<0) != 0) {
		flcEnabled = true
	}
	return sgxEnabled, flcEnabled, nil
}

func cpuid_low(arg1, arg2 uint32) (eax, ebx, ecx, edx uint32)

func isCPUSupportsSGXExtensions() bool {
	sgxExtensionsEnabled := false
	_, ebx, _, _ := cpuid_low(7, 0)
	if ((ebx >> 2) & 1) != 0 { // 2nd bit should be set if SGX extensions are supported.
		sgxExtensionsEnabled = true
	}
	return sgxExtensionsEnabled
}

func epcMemoryDetails() (epcOffset, epcSize string) {
	eax, ebx, ecx, edx := cpuid_low(18, 2)
	log.Debugf("eax, ebx, ecx, edx: %08x-%08x-%08x-%08x", eax, ebx, ecx, edx)
	// eax(31, 12) + ebx(51, 32)
	range1 := uint64((((1 << 20) - 1) & (eax >> 12)))
	range2 := uint64(((1 << 20) - 1) & ebx)
	startAddress := (range2 << 32) | (range1 << 12)
	log.Debugf("startaddress: %08x", startAddress)

	// ecx(31, 12) + edx(51, 32)
	range1 = uint64(((1 << 20) - 1) & (ecx >> 12))
	range2 = uint64(((1 << 20) - 1) & edx)
	size := (range2 << 32) | (range1 << 12)
	sizeINMB := convertToMB(size)
	startAddressinHex := "0x" + fmt.Sprintf("%08x", startAddress)
	log.Debugf("size in decimal %20d  and mb %16q: ", size, sizeINMB)
	return startAddressinHex, sizeINMB
}

func isSGXInstructionSetSuported() int {
	cpuid.Detect()
	sgxInstructionSet := 0
	if cpuid.CPU.SGX.SGX1Supported {
		sgxInstructionSet = 1
		if cpuid.CPU.SGX.SGX2Supported {
			sgxInstructionSet = 2
		}
	} else {
		log.Debug("SGX instruction set 1 and 2 are not supported.")
	}
	return sgxInstructionSet
}

func maxEnclaveSize() (maxSizeNot64, maxSize64 int64) {
	cpuid.Detect()
	return cpuid.CPU.SGX.MaxEnclaveSizeNot64, cpuid.CPU.SGX.MaxEnclaveSize64
}

func writePCKDetails() (string, error) {
	_, err := utils.ReadAndParseFromCommandLine(pckIDRetrievalInfo)
	if err != nil {
		return "", err
	}
	fileContents := ""
	// check if file exists in the directory then parse it and write the values in log file.
	if _, err := os.Stat("/opt/pckData"); err == nil {
		// path/to/whatever exists
		dat, err := ioutil.ReadFile("/opt/pckData")
		if err != nil {
			log.Error("could not read sgx platform values from pckData file")
		} else {
			fileContents = string(dat)
		}
	} else if os.IsNotExist(err) {
		// path/to/whatever does *not* exist
		log.Warning("pcData file not found")
	} else {
		log.Warning("unknown error while reading pckData file")
	}
	return fileContents, err
}

func convertToMB(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB",
		float64(b)/float64(div), "kMGTPE"[exp])
}

func PushSGXData(pdata *PlatformData) (bool, error) {
	log.Trace("resource/sgx_detection.go: PushSGXData() Entering")
	defer log.Trace("resource/sgx_detection.go: PushSGXData() Leaving")
	client, err := clients.HTTPClientWithCADir(constants.TrustedCAsStoreDir)
	if err != nil {
		return false, errors.Wrap(err, "PushSGXData: Error in getting client object")
	}

	conf := config.Global()
	if conf == nil {
		return false, errors.Wrap(errors.New("PushSGXData: Configuration pointer is null"), "Config error")
	}

	pushURL := conf.ScsBaseURL + "/certification/v1/platforms"
	log.Debug("PushSGXData: URL: ", pushURL)

	requestStr := map[string]string{
		"enc_ppid": pdata.EncryptedPPID,
		"cpu_svn":  pdata.CPUSvn,
		"pce_svn":  pdata.PceSvn,
		"pce_id":   pdata.PceID,
		"qe_id":    pdata.QeID,
		"manifest": pdata.Manifest}

	reqBytes, err := json.Marshal(requestStr)

	if err != nil {
		return false, errors.Wrap(err, "PushSGXData: Marshal error:"+err.Error())
	}

	req, err := http.NewRequest("POST", pushURL, bytes.NewBuffer(reqBytes))
	if err != nil {
		return false, errors.Wrap(err, "PushSGXData: Failed to Get New request")
	}

	req.Header.Set("Content-Type", "application/json")
	err = utils.AddJWTToken(req)
	if err != nil {
		return false, errors.Wrap(err, "PushSGXData: Failed to add JWT token to the authorization header")
	}

	resp, err := client.Do(req)
	if resp != nil && resp.StatusCode == http.StatusUnauthorized {
		// fetch token and try again
		utils.AasRWLock.Lock()
		err = utils.AasClient.FetchAllTokens()
		if err != nil {
			return false, errors.Wrap(err, "PushSGXData: FetchAllTokens() Could not fetch token")
		}
		utils.AasRWLock.Unlock()
		err = utils.AddJWTToken(req)
		if err != nil {
			return false, errors.Wrap(err, "PushSGXData: Failed to add JWT token to the authorization header")
		}

		req.Body = ioutil.NopCloser(bytes.NewBuffer(reqBytes))
		resp, err = client.Do(req)
	}

	var retries int = 0
	var timeBwCalls int = conf.WaitTime

	if err != nil || (resp != nil && resp.StatusCode >= http.StatusInternalServerError) {

		for {
			log.Errorf("Retrying for '%d'th time: ", retries)
			req.Body = ioutil.NopCloser(bytes.NewBuffer(reqBytes))
			resp, err = client.Do(req)

			if resp != nil && resp.StatusCode < http.StatusInternalServerError {
				log.Info("PushSGXData: Status code received: " + strconv.Itoa(resp.StatusCode))
				log.Debug("PushSGXData: Retry count now: " + strconv.Itoa(retries))
				break
			}

			if err != nil {
				log.WithError(err).Info("PushSGXData:")
			}

			if resp != nil {
				log.Error("PushSGXData: Invalid status code received: " + strconv.Itoa(resp.StatusCode))
			}

			retries++
			if retries >= conf.RetryCount {
				log.Errorf("PushSGXData: Retried %d times, Sleeping %d minutes...", conf.RetryCount, timeBwCalls)
				time.Sleep(time.Duration(timeBwCalls) * time.Minute)
				retries = 0
			}
		}
	}

	if resp != nil && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		err = resp.Body.Close()
		if err != nil {
			log.WithError(err).Error("Error closing response")
		}
		return false, errors.New("PushSGXData: Invalid status code received: " + strconv.Itoa(resp.StatusCode))
	}

	var pushResponse SCSPushResponse

	dec := json.NewDecoder(resp.Body)
	dec.DisallowUnknownFields()

	err = dec.Decode(&pushResponse)
	if err != nil {
		return false, errors.Wrap(err, "PushSGXData: Read Response failed")
	}

	log.Debug("PushSGXData: Received SCS Response Data: ", pushResponse)
	err = resp.Body.Close()
	if err != nil {
		log.WithError(err).Error("Error closing response")
	}
	return true, nil
}
