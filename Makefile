SHELL := /bin/bash
GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
GITCOMMIT := $(shell git describe --always)
GITCOMMITDATE := $(shell git log -1 --date=short --pretty=format:%cd)
VERSION := $(or ${GITTAG}, v0.0.0)

PROXY_EXISTS := $(shell if [[ "${https_proxy}" || "${http_proxy}" ]]; then echo 1; else echo 0; fi)
.PHONY: sgx_agent installer all test clean

sgx_agent:
	env GOOS=linux go build -ldflags "-X intel/isecl/sgx_agent/version.Version=$(VERSION) -X intel/isecl/sgx_agent/version.GitHash=$(GITCOMMIT)" -o out/sgx_agent

installer: sgx_agent
	mkdir -p out/installer
	cp dist/linux/sgx_agent.service out/installer/sgx_agent.service
	cp dist/linux/install.sh out/installer/install.sh && chmod +x out/installer/install.sh
	cp out/sgx_agent out/installer/sgx_agent
	makeself out/installer out/sgx_agent-$(VERSION).bin "SGX Agent Discovery $(VERSION)" ./install.sh

clean:
	rm -f cover.*
	rm -f sgx_agent
	rm -rf out/
