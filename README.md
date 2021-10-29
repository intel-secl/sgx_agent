# SGX Agent

`SGX Agent` is primarily involved in SGX technology discovery and collection of SGX attributes on a SGX enabled platform (Single Socket/Multi socket).

## Key features

- SGX agent required for SGX Discovery and Provisioning
- Collects the SGX platform-specific values, explicitly Encrypted PPID, CPU SVN, ISV SVN, PCE ID, Manifest and QEID
- SGX Agent provides platform SGX-related information to the SGX Host Verification Service

## System Requirements

- RHEL 8.2
- Epel 8 Repo
- Proxy settings if applicable
- SHVS should be up and running

## Software requirements

- git
- makeself
- docker
- Go 1.16.7

# Step By Step Build Instructions

## Install required shell commands

### Install tools from `dnf`

```{.shell}
sudo dnf install -y git wget makeself docker
```

### Install `go 1.16.7`

The `Certificate Management Service` requires Go version 1.16 that has support for `go modules`. The build was validated with version 1.16.7 version of `go`. It is recommended that you use a newer version of `go`

- but please keep in mind that the product has been validated with 1.16.7 and newer versions of `go` may introduce compatibility issues. You can use the following to install `go`.

```{.shell}
wget https://dl.google.com/go/go1.16.7.linux-amd64.tar.gz
tar -xzf go1.16.7.linux-amd64.tar.gz
sudo mv go /usr/local
export GOROOT=/usr/local/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
```

## Build SGX Agent

- Git clone the SGX Agent
- Run scripts to build the SGX Agent

```{.shell}
git clone https://github.com/intel-secl/utils.git && cd utils
git checkout v4.1.0
cd builds/skc-tools/sgx_agent/build_scripts

- To build SGX Agent,
#./sgxagent_build.sh
- This script will generate a tarball(sgx_agent.tar) and checksum file(sgx_agent.sha2)
- Copy sgx_agent.tar, sgx_agent.sha2 and untar.sh(from sgx_agent directory) to a directory in the deployment machine
```

### Manage service

- Start service

  - sgx_agent start

- Stop service

  - sgx_agent stop

- Status of service

  - sgx_agent status

## Third Party Dependencies

- Certificate Management Service

- Authentication and Authorization Service

### Direct dependencies

Name    | Repo URL                     | Minimum Version Required
------- | ---------------------------- | :-----------------------
uuid    | github.com/google/uuid       | v1.1.2
cpuid   | github.com/klauspost/cpuid   | v1.2.1
errors  | github.com/pkg/errors        | v0.9.1
logrus  | github.com/sirupsen/logrus   | v1.4.0
testify | github.com/stretchr/testify  | v1.3.0
jwt-go  | github.com/dgrijalva/jwt-go  | v3.2.1
testify | github.com/stretchr/testify  | v1.3.0
yaml.v2 | gopkg.in/yaml.v2             | v2.4.0
common  | github.com/intel-secl/common | v3.5.0
clients | github.com/intel-secl/client | v3.5.0

_Note: All dependencies are listed in go.mod_
