/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package resource

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/klauspost/cpuid"
	"github.com/pkg/errors"
	"intel/isecl/lib/clients/v3"
	"intel/isecl/sgx_agent/v3/config"
	"intel/isecl/sgx_agent/v3/constants"
	"intel/isecl/sgx_agent/v3/utils"

	"bytes"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

///MSR.IA32_Feature_Control register tells availability of SGX
const (
	IA32_FEATURE_CONTROL_REGISTER = 0x3A
	MSR_DEVICE                    = "/dev/cpu/0/msr"
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

type Platform_Data struct {
	Encrypted_PPID string `json:"enc-ppid"`
	Pce_id         string `json:"pceid"`
	Cpu_svn        string `json:"cpusvn"`
	Pce_svn        string `json:"pcesvn"`
	Qe_id          string `json:"qeid"`
	Manifest       string `json:"Manifest"`
}

type PlatformResponse struct {
	SGXData SGX_Discovery_Data `json:"sgx-data"`
	PData   Platform_Data      `json:"sgx-platform-data"`
}

var (
	pckIDRetrievalInfo = []string{"PCKIDRetrievalTool", "-f", "/opt/pckData"}
)

type SCSPushResponse struct {
	Status  string `json:"Status"`
	Message string `json:"Message"`
}

//Exported globally.
var sgxData SGX_Discovery_Data
var platformData Platform_Data

func ProvidePlatformInfo(router *mux.Router) {
	log.Trace("resource/sgx_detection:ProvidePlatformInfo() Entering")
	defer log.Trace("resource/sgx_detection:ProvidePlatformInfo() Leaving")

	router.Handle("/host", handlers.ContentTypeHandler(getPlatformInfo(), "application/json")).Methods("GET")
}

///For any demo function
func Extract_SGXPlatformValues() (error, *SGX_Discovery_Data, *Platform_Data) {
	var sgx_enablement_info *SGX_Discovery_Data
	var sgx_platform_data *Platform_Data

	sgxExtensionsEnabled := isCPUSupportsSGXExtensions()
	if !sgxExtensionsEnabled {
		log.Info("SGX Extensions aren't enabled. Not proceeding.")
		return nil, nil, nil
	}
	log.Info("SGX Extensions are enabled, hence proceeding further")
	sgxData.Sgx_supported = sgxExtensionsEnabled
	sgxEnabled, flcEnabled, err := isSGXAndFLCEnabled()
	if err != nil {
		return errors.Wrap(err, "Error while checking SGX and FLC are enabled in MSR"), nil, nil
	}
	sgxData.Sgx_enabled = sgxEnabled
	sgxData.Flc_enabled = flcEnabled

	EPCStartAddress, EPCSize := epcMemoryDetails()
	sgxData.Epc_startaddress = EPCStartAddress
	sgxData.Epc_size = EPCSize
	sgxValue := isSGXInstructionSetSuported()
	sgxData.sgx_Level = sgxValue
	var maxEnclaveSizeNot64Val, maxEnclaveSize64Val = maxEnclaveSize()
	sgxData.maxEnclaveSizeNot64 = maxEnclaveSizeNot64Val
	sgxData.maxEnclaveSize64 = maxEnclaveSize64Val

	log.Debug("**********************************SGX SPECIFIC VALUES*****************************")
	log.Debug("sgx supported: ", sgxExtensionsEnabled)
	log.Debug("sgx enabled: ", sgxEnabled)
	log.Debug("flc enabled: ", flcEnabled)
	log.Debug("Start Address: ", EPCStartAddress)
	log.Debug("Size: ", EPCSize)
	log.Debug("SGXLevel Supported: ", sgxValue)
	log.Debug("Enclave size when CPU is not in 64 bit mode: ", maxEnclaveSizeNot64Val)
	log.Debug("Enclave size when CPU is in 64 bit mode: ", maxEnclaveSize64Val)

	sgx_enablement_info = &sgxData

	if sgxEnabled && flcEnabled {
		log.Info("sgx and flc is enabled. Hence running PCKIDRetrieval tool")
		fileContents, err := writePCKDetails()
		if err == nil {
			///Parse the string as retrieved.
			s := strings.Split(fileContents, ",")
			log.Debug("EncryptedPPID: ", s[0])
			log.Debug("PCE_ID: ", s[1])
			log.Debug("CPUSVN: ", s[2])
			log.Debug("PCE ISVSVN: ", s[3])
			log.Debug("QE_ID: ", s[4])

			platformData.Encrypted_PPID = s[0]
			platformData.Pce_id = s[1]
			platformData.Cpu_svn = s[2]
			platformData.Pce_svn = s[3]
			platformData.Qe_id = s[4]
			if len(s) > 5 {
				log.Debug("Manifest exists. This is a multi-package platform")
				platformData.Manifest = s[5]
			}
			//FIXME : Local Copy 
			sgx_platform_data = &platformData
		} else {
			log.WithError(err).Info("fileContents not retrieved from PCKIDRetrivalTool")
			return err, nil , nil
		}
	} else {
		log.Info("sgx and flc are not enabled. Hence not running PCKIDRetrieval tool")
		err := errors.New("unsupported")
		return err, nil, nil
	}
	return nil, sgx_enablement_info, sgx_platform_data
}

// Utility function that reads an unsigned long long from /dev/cpu/0/msr at offset
// 'offset'
func ReadMSR(offset int64) (uint64, error) {

	msr, err := os.Open(MSR_DEVICE)
	if err != nil {
		return 0, errors.Wrapf(err, "sgx_detection:ReadMSR(): Error opening msr")
	}

	_, err = msr.Seek(offset, 0)
	if err != nil {
		return 0, errors.Wrapf(err, "sgx_detection:ReadMSR(): Could not seek to location %x", offset)
	}

	results := make([]byte, 8)
	len, err := msr.Read(results)
	if err != nil {
		return 0, errors.Wrapf(err, "sgx_detection:ReadMSR(): There was an error reading msr at offset %x", offset)
	}
	if len < 8 {
		return 0, errors.New("sgx_detection:ReadMSR(): Reading the msr returned the incorrect length")
	}

	err = msr.Close()
	if err != nil {
		return 0, errors.Wrapf(err, "sgx_detection:ReadMSR(): Error while closing msr device file")
	}

	return binary.LittleEndian.Uint64(results), nil
}

func isSGXAndFLCEnabled() (sgxEnabled bool, flcEnabled bool, err error) {
	sgxEnabled = false
	flcEnabled = false
	sgxBits, err := ReadMSR(IA32_FEATURE_CONTROL_REGISTER)
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
	sgx_extensions_enabled := false
	_, ebx, _, _ := cpuid_low(7, 0)
	if ((ebx >> 2) & 1) != 0 { ///2nd bit should be set if SGX extensions are supported.
		sgx_extensions_enabled = true
	}
	return sgx_extensions_enabled
}

func epcMemoryDetails() (string, string) {
	eax, ebx, ecx, edx := cpuid_low(18, 2)
	log.Debugf("eax, ebx, ecx, edx: %08x-%08x-%08x-%08x", eax, ebx, ecx, edx)
	//eax(31, 12) + ebx(51, 32)
	range1 := (((1 << 20) - 1) & (eax >> (13 - 1)))
	range2 := ((1 << 20) - 1) & (ebx >> (32 - 1))
	startAddress := ((range2 & 0xff) | range1) << 12
	log.Debugf("startaddress: %08x", startAddress)

	//ecx(31, 12) + edx(51, 32)
	range1 = ((1 << 20) - 1) & (ecx >> (13 - 1))
	range2 = ((1 << 20) - 1) & (edx >> (32 - 1))
	size := ((range2 & 0xff) | range1) << 12
	sizeINMB := convertToMB(size)
	startAddressinHex := "0x" + fmt.Sprintf("%08x", startAddress)
	log.Debugf("size in decimal %20d  and mb %16q: ", size, sizeINMB)
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
		log.Debug("SGX instruction set 1 and 2 are not supported.")
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
		log.Warning("File not found")
	} else {
		log.Warning("some issue in reading file")
	}
	return fileContents, err
}

func getPlatformInfo() errorHandlerFunc {
	return func(httpWriter http.ResponseWriter, httpRequest *http.Request) error {
		log.Trace("resource/sgx_detection:GetPlatformInfo() Entering")
		defer log.Trace("resource/sgx_detection:GetPlatformInfo() Leaving")

		err := authorizeEndpoint(httpRequest, constants.HostDataReaderGroupName, true)
		if err != nil {
			return err
		}

		if httpRequest.Header.Get("Accept") != "application/json" {
			return &resourceError{Message: "Accept type not supported", StatusCode: http.StatusNotAcceptable}
		}

		conf := config.Global()
		if conf == nil {
			return errors.Wrap(errors.New("getPlatformInfo: Configuration pointer is null"), "Config error")
		}

		res := PlatformResponse{SGXData: sgxData, PData: platformData}

		httpWriter.Header().Set("Content-Type", "application/json")
		httpWriter.WriteHeader(http.StatusOK)
		js, err := json.Marshal(res)
		if err != nil {
			log.Debug("Marshalling unsuccessful")
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		_, err = httpWriter.Write(js)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		slog.Info("Platform data retrieved by:", httpRequest.RemoteAddr)
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

func PushSGXData(pdata *Platform_Data) (bool, error) {
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

	pushUrl := conf.ScsBaseUrl + "/platforminfo/push"
	log.Debug("PushSGXData: URL: ", pushUrl)
	log.Debug("qe_id",    pdata.Qe_id)


	requestStr := map[string]string{
		"enc_ppid": pdata.Encrypted_PPID,
		"cpu_svn":  pdata.Cpu_svn,
		"pce_svn":  pdata.Pce_svn,
		"pce_id":   pdata.Pce_id,
		"qe_id":    pdata.Qe_id,
		"manifest": pdata.Manifest}

	reqBytes, err := json.Marshal(requestStr)
	log.Debug ("Request JSON length : " , reqBytes)

	if err != nil {
		return false, errors.Wrap(err, "PushSGXData: Marshal error:"+err.Error())
	}

	req, err := http.NewRequest("POST", pushUrl, bytes.NewBuffer(reqBytes))
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
	var time_bw_calls int = conf.WaitTime

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

			retries += 1
			if retries >= conf.RetryCount {
				log.Errorf("PushSGXData: Retried %d times, Sleeping %d minutes...", conf.RetryCount, time_bw_calls)
				time.Sleep(time.Duration(time_bw_calls) * time.Minute)
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

