# SGX Agent

`SGX Agent` is primarily involved in SGX technology discovery and collection of SGX attributes on a SGX enabled platform (Single Socket/Multi socket).

## Key features

- SGX agent required for SGX Discovery and Provisioning
- Collects the SGX platform-specific values, explicitly Encrypted PPID, CPU SVN, ISV SVN, PCE ID, Manifest and QEID
- SGX Agent provides platform SGX-related information to the SGX Host Verification Service

## System Requirements

- RHEL 8.4 or ubuntu 20.04
- Epel 8 Repo
- Proxy settings if applicable
- SHVS should be up and running

## Software requirements

- git
- makeself
- docker
- Go 1.18.8

# Step By Step Build Instructions

## Install required shell commands

### Install tools from `dnf`

```{.shell}
sudo dnf install -y git wget makeself docker
```

### Install `go 1.18.8`

The `Certificate Management Service` requires Go version 1.18 that has support for `go modules`. The build was validated with version 1.18.8 version of `go`. It is recommended that you use a newer version of `go`

- but please keep in mind that the product has been validated with 1.18.8 and newer versions of `go` may introduce compatibility issues. You can use the following to install `go`.

```{.shell}
wget https://dl.google.com/go/go1.18.8.linux-amd64.tar.gz
tar -xzf go1.18.8.linux-amd64.tar.gz
sudo mv go /usr/local
export GOROOT=/usr/local/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
```

## Build SGX Agent

- Git clone the SGX Agent
- Run scripts to build the SGX Agent

```{.shell}
repo init -u  https://github.com/intel-secl/build-manifest.git -b refs/tags/v5.0.0 -m manifest/skc.xml 
repo sync 
make sgx_agent_k8s 
- Sgx agent container image will be generated. Use: `docker images` to list 
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

| Name        | Repo URL                    | Minimum Version Required  |
| ----------- | --------------------------- | :-----------------------  |
| uuid        | github.com/google/uuid      | v1.2.0                    |
| cpuid       | github.com/klauspost/cpuid  | v1.2.1                    |
| errors      | github.com/pkg/errors       | v0.9.1                    |
| logrus      | github.com/sirupsen/logrus  | v1.7.0                    |
| jwt-go      | github.com/dgrijalva/jwt-go | v3.2.1                    |
| testify     | github.com/stretchr/testify | v1.6.1                    |
| yaml.v3     | gopkg.in/yaml.v3            | v3.0.1                    |
| common      | github.com/intel-secl/common| v5.0.0                    |
| clients     | github.com/intel-secl/client| v5.0.0                    |


*Note: All dependencies are listed in go.mod*
