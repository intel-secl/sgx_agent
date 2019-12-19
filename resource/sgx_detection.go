/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package resource

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/klauspost/cpuid"
	"intel/isecl/sgx_agent/utils"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
)

type SGX_Discovery_Data struct {
	Sgx_supported       bool   `json:"sgx-supported"`
	Sgx_enabled         bool   `json:"sgx-enabled"`
	Flc_enabled         bool   `json:"flc-enabled"`
	Epc_startaddress    string `json:"epc-offset"`
	Epc_size            string `json:"epc-size"`
	sgx_Level           int
	maxEnclaveSizeNot64 int64
	maxEnclaveSize64    int64
}

type Paltform_Data struct {
	Encrypted_PPID string `json:"enc-ppid"`
	Pce_id         string `json:"pceid"`
	Cpu_svn        string `json:"cpusvn"`
	Pce_svn        string `json:"pcesvn"`
	Qe_id          string `json:"qeid"`
}

type PlatformResponse struct {
	S1 SGX_Discovery_Data `json:"sgx-data"`
	P1 Paltform_Data      `json:"sgx-platform-data"`
}

var (
	flcEnabledCmd      = []string{"rdmsr", "-ax", "0x3A"} ///MSR.IA32_Feature_Control register tells availability of SGX
	pckIDRetrievalInfo = []string{"PCKIDRetrievalTool", "-f", "/opt/pckData"}
)

var data1 SGX_Discovery_Data
var data2 Paltform_Data

func ProvidePlatformInfo(router *mux.Router) {
	log.Trace("resource/sgx_detection:ProvidePlatformInfo() Entering")
	defer log.Trace("resource/sgx_detection:ProvidePlatformInfo() Leaving")

	router.Handle("/host", handlers.ContentTypeHandler(GetPlatformInfo(), "application/json")).Methods("GET")
}

///For any demo function
func Extract_SGXPlatformValues() error {
	sgxExtensionsEnabled := isCPUSupportsSGXExtensions()
	if !sgxExtensionsEnabled {
		log.Info("SGX Extensions aren't enabled. Not proceeding.")
		return nil
	}
	log.Info("SGX Extensions are enabled, hence proceeding further")
	data1.Sgx_supported = sgxExtensionsEnabled
	sgxEnabled, err := isSGXEnabled()
	if err != nil {
		log.Debug("SGXEnabled can't be determined", err)
		return err
	}
	data1.Sgx_enabled = sgxEnabled
	flcEnabled, err := isFLCEnabled()
	data1.Flc_enabled = flcEnabled
	if err != nil {
		log.Error("error came in isFLCEnabled()")
		return err
	}
	EPCStartAddress, EPCSize := epcMemoryDetails()
	data1.Epc_startaddress = EPCStartAddress
	data1.Epc_size = EPCSize
	sgxValue := isSGXInstructionSetSuported()
	data1.sgx_Level = sgxValue
	var maxEnclaveSizeNot64Val, maxEnclaveSize64Val = maxEnclaveSize()
	data1.maxEnclaveSizeNot64 = maxEnclaveSizeNot64Val
	data1.maxEnclaveSize64 = maxEnclaveSize64Val

	log.Info("**********************************SGX SPECIFIC VALUES*****************************")
	log.Info("sgx supported: ", sgxExtensionsEnabled)
	log.Info("sgx enabled: ", sgxEnabled)
	log.Info("flc enabled: ", flcEnabled)
	log.Info("Start Address: ", EPCStartAddress)
	log.Info("Size: ", EPCSize)
	log.Info("SGXLevel Supported: ", sgxValue)
	log.Info("Enclave size when CPU is not in 64 bit mode: ", maxEnclaveSizeNot64Val)
	log.Info("Enclave size when CPU is in 64 bit mode: ", maxEnclaveSize64Val)
	if sgxEnabled && flcEnabled {
		log.Info("sgx and flc is enabled. Hence running PCKIDRetrieval tool")
		fileContents, err := writePCKDetails()
		if err == nil {
			///Parse the string as retrieved.
			s := strings.Split(fileContents, ",")
			log.Info("EncryptedPPID: ", s[0])
			log.Info("PCE_ID: ", s[1])
			log.Info("CPUSVN: ", s[2])
			log.Info("PCE ISVSVN: ", s[3])
			log.Info("QE_ID: ", s[4])
			data2.Encrypted_PPID = s[0]
			data2.Pce_id = s[1]
			data2.Cpu_svn = s[2]
			data2.Pce_svn = s[3]
			data2.Qe_id = s[4]
		} else {
			log.Error("fileContents not retrieved from PCKIDRetrivalTool")
			return err
		}
	} else {
		log.Info("sgx and flc are not enable. Hence not running PCKIDRetrieval tool")
	}
	return nil
}

///This is done in TA but we might need to do here
func isSGXEnabled() (bool, error) {
	result, err := utils.ReadAndParseFromCommandLine(flcEnabledCmd)
	if err != nil {
		return false, nil
	}
	sgxStatus := false
	registerValue := result[0]
	val, error := strconv.ParseInt(registerValue, 16, 64)
	if error != nil {
		return false, nil
	}

	if (((val >> 18) & 1) != 0) && ((val)&1 != 0) { ///18th bit stands for IA32_FEATURE_CONTROL. 0th bit should be set to 1.
		sgxStatus = true
	}
	return sgxStatus, err
}

func isFLCEnabled() (bool, error) {
	result, err := utils.ReadAndParseFromCommandLine(flcEnabledCmd)
	if err != nil {
		return false, nil
	}
	sgxStatus := false
	registerValue := result[0]
	val, error := strconv.ParseInt(registerValue, 16, 64)
	if error != nil {
		return false, nil
	}
	if (((val >> 17) & 1) != 0) && ((val)&1 != 0) { ///17th bit stands for IA32_FEATURE_CONTROL. 0th bit should be ste to 1.
		sgxStatus = true
	}
	return sgxStatus, err
}

func cpuid_low(arg1, arg2 uint32) (eax, ebx, ecx, edx uint32)

func isCPUSupportsSGXExtensions() bool {
	sgx_extensions_enabled := false
	_, ebx, _, _ := cpuid_low(7, 0)
	if ((ebx >> 2) & 1) != 0 { ///2nd bit should be set if SGX extensions are supported.
		sgx_extensions_enabled = true
	}
	return sgx_extensions_enabled
}

func epcMemoryDetails() (string, string) {
	eax, ebx, ecx, edx := cpuid_low(18, 2)
	log.Infof("eax, ebx, ecx, edx: %08x-%08x-%08x-%08x", eax, ebx, ecx, edx)
	//eax(31, 12) + ebx(51, 32)
	range1 := (((1 << 20) - 1) & (eax >> (13 - 1)))
	range2 := ((1 << 20) - 1) & (ebx >> (32 - 1))
	startAddress := ((range2 & 0xff) | range1) << 12
	log.Infof("startaddress: %08x", startAddress)

	//ecx(31, 12) + edx(51, 32)
	range1 = ((1 << 20) - 1) & (ecx >> (13 - 1))
	range2 = ((1 << 20) - 1) & (edx >> (32 - 1))
	size := ((range2 & 0xff) | range1) << 12
	sizeINMB := convertToMB(size)
	startAddressinHex := "0x" + fmt.Sprintf("%08x", startAddress)
	log.Infof("size in decimal %20d  and mb %16q: ", size, sizeINMB)
	return startAddressinHex, sizeINMB
}

func isSGXInstructionSetSuported() int {
	cpuid.Detect()
	sgx_value := 0
	if cpuid.CPU.SGX.SGX1Supported {
		sgx_value = 1
		if cpuid.CPU.SGX.SGX2Supported {
			sgx_value = 2
		}
	} else {
		log.Info("SGX instrusction set 1 or 2 neither is supported.")
	}
	return sgx_value
}

func maxEnclaveSize() (int64, int64) {
	cpuid.Detect()
	return cpuid.CPU.SGX.MaxEnclaveSizeNot64, cpuid.CPU.SGX.MaxEnclaveSize64
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func writePCKDetails() (string, error) {
	_, err := utils.ReadAndParseFromCommandLine(pckIDRetrievalInfo)
	if err != nil {
		return "", err
	}
	fileContents := ""
	///check if file exists in the directory then parse it and write the values in log file.
	if _, err := os.Stat("/opt/pckData"); err == nil {
		// path/to/whatever exists
		dat, err := ioutil.ReadFile("/opt/pckData")
		check(err)
		fileContents = string(dat[:])
	} else if os.IsNotExist(err) {
		// path/to/whatever does *not* exist
		log.Info("File not found")
	} else {
		log.Info("some issue in reading file")
	}
	return fileContents, err
}

func GetPlatformInfo() errorHandlerFunc {
	return func(httpWriter http.ResponseWriter, httpRequest *http.Request) error {
		log.Trace("resource/sgx_detection:GetPlatformInfo() Entering")
		defer log.Trace("resource/sgx_detection:GetPlatformInfo() Leaving")
		if httpRequest.Header.Get("Accept") != "application/json" {
			return &resourceError{Message: "Accept type not supported", StatusCode: http.StatusNotAcceptable}
		}

		res := PlatformResponse{S1: data1, P1: data2}

		httpWriter.Header().Set("Content-Type", "application/json")
		httpWriter.WriteHeader(http.StatusOK)
		js, err := json.Marshal(res)
		if err != nil {
			log.Debug("Marshalling unsuccessful")
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}

		httpWriter.Write(js)
		log.Trace("resource/sgx_detection:GetPlatformInfo() Returned requested")
		return nil
	}
}

func convertToMB(b uint32) string {
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
