SHELL := /bin/bash
GITCOMMIT := $(shell git describe --always)
VERSION := "v5.1.0"
BUILDDATE := $(shell TZ=UTC date +%Y-%m-%dT%H:%M:%S%z)
PROXY_EXISTS := $(shell if [[ "${https_proxy}" || "${http_proxy}" ]]; then echo 1; else echo 0; fi)
DOCKER_PROXY_FLAGS := ""
MONOREPO_GITURL := "https://github.com/intel-innersource/applications.security.isecl.intel-secl.git"
MONOREPO_GITBRANCH := "v5.1/develop"

ifeq ($(PROXY_EXISTS),1)
	DOCKER_PROXY_FLAGS = --build-arg http_proxy=${http_proxy} --build-arg https_proxy=${https_proxy}
endif

.PHONY: sgx_agent installer docker all clean

all: clean installer

installer: sgx_agent
	mkdir -p out/installer
	cp dist/linux/sgx_agent.service out/installer/sgx_agent.service
	cp dist/linux/install.sh out/installer/install.sh && chmod +x out/installer/install.sh
	cp out/sgx_agent out/installer/sgx_agent

	git clone --depth 1 -b $(MONOREPO_GITBRANCH) $(MONOREPO_GITURL) tmp_monorepo
	cp -a tmp_monorepo/pkg/lib/common/upgrades/* out/installer/
	rm -rf tmp_monorepo
	cp -a upgrades/* out/installer
	mv out/installer/build/* out/installer
	chmod +x out/installer/*.sh

	makeself out/installer out/sgx_agent-$(VERSION).bin "SGX Agent $(VERSION)" ./install.sh

sgx_agent:
	env GOOS=linux GOSUMDB=off GOPROXY=direct go mod tidy && env GOOS=linux GOSUMDB=off GOPROXY=direct go build -ldflags "-X intel/isecl/sgx_agent/v5/version.BuildDate=$(BUILDDATE) -X intel/isecl/sgx_agent/v5/version.Version=$(VERSION) -X intel/isecl/sgx_agent/v5/version.GitHash=$(GITCOMMIT)" -o out/sgx_agent

docker: sgx_agent
ifeq ($(PROXY_EXISTS),1)
	docker build ${DOCKER_PROXY_FLAGS} --label org.label-schema.build-date=$(BUILDDATE) -f dist/image/Dockerfile -t $(DOCKER_REGISTRY)isecl/sgx_agent:$(VERSION)-$(GITCOMMIT) .
else
	docker build -f dist/image/Dockerfile --label org.label-schema.build-date=$(BUILDDATE) -t $(DOCKER_REGISTRY)isecl/sgx_agent:$(VERSION)-$(GITCOMMIT) .
endif
	docker save $(DOCKER_REGISTRY)isecl/sgx_agent:$(VERSION)-$(GITCOMMIT) > out/sgx-agent-$(VERSION)-$(GITCOMMIT).tar

test:
	env GOOS=linux GOSUMDB=off GOPROXY=direct go mod tidy
	go test ./... -coverprofile cover.out
	go tool cover -func cover.out
	go tool cover -html=cover.out -o cover.html

docker_stacks: sgx_agent
ifeq ($(PROXY_EXISTS),1)
	docker build ${DOCKER_PROXY_FLAGS} -f dist/image/Dockerfile_stacks -t $(DOCKER_REGISTRY)isecl/sgx_agent:$(VERSION)-$(GITCOMMIT) .
else
	docker build -f dist/image/Dockerfile_stacks -t $(DOCKER_REGISTRY)isecl/sgx_agent:$(VERSION)-$(GITCOMMIT) .
endif
	docker save $(DOCKER_REGISTRY)isecl/sgx_agent:$(VERSION)-$(GITCOMMIT) > out/sgx-agent-$(VERSION)-$(GITCOMMIT).tar

oci-archive: docker
	skopeo copy docker-daemon:$(DOCKER_REGISTRY)isecl/sgx_agent:$(VERSION)-$(GITCOMMIT) oci-archive:out/sgx-agent-$(VERSION)-$(GITCOMMIT).tar

oci-archive_stacks: docker_stacks
	skopeo copy docker-daemon:$(DOCKER_REGISTRY)isecl/sgx_agent:$(VERSION)-$(GITCOMMIT) oci-archive:out/sgx-agent-$(VERSION)-$(GITCOMMIT).tar

sgx_agent-docker-push: docker
	docker tag $(DOCKER_REGISTRY)isecl/sgx_agent:$(VERSION)-$(GITCOMMIT) $(DOCKER_REGISTRY)isecl/sgx_agent:$(VERSION)
	docker push $(DOCKER_REGISTRY)isecl/sgx_agent:$(VERSION)
	docker push $(DOCKER_REGISTRY)isecl/sgx_agent:$(VERSION)-$(GITCOMMIT)

clean:
	rm -f cover.*
	rm -rf out/
