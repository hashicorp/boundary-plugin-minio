module github.com/hashicorp/boundary-plugin-minio

go 1.22.2

replace github.com/hashicorp/boundary/sdk v0.0.42 => github.com/hashicorp/boundary-enterprise/sdk v0.0.36-0.20240604060311-9c1d9374df0f

require (
	github.com/google/go-cmp v0.6.0
	github.com/google/uuid v1.5.0
	github.com/hashicorp/boundary/sdk v0.0.42
	github.com/minio/madmin-go/v3 v3.0.48
	github.com/minio/minio-go/v7 v7.0.67
	github.com/ory/dockertest/v3 v3.10.0
	github.com/stretchr/testify v1.8.4
	google.golang.org/grpc v1.61.0
	google.golang.org/protobuf v1.33.0
)

require (
	github.com/Azure/go-ansiterm v0.0.0-20170929234023-d6e3b3328b78 // indirect
	github.com/Microsoft/go-winio v0.6.0 // indirect
	github.com/Nvveen/Gotty v0.0.0-20120604004816-cd527374f1e5 // indirect
	github.com/cenkalti/backoff/v4 v4.1.3 // indirect
	github.com/containerd/continuity v0.3.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/docker/cli v20.10.17+incompatible // indirect
	github.com/docker/docker v24.0.9+incompatible // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.0 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/eventlogger v0.2.6-0.20231025104552-802587e608f0 // indirect
	github.com/hashicorp/eventlogger/filters/encrypt v0.1.8-0.20231025104552-802587e608f0 // indirect
	github.com/hashicorp/go-kms-wrapping/v2 v2.0.14 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/imdario/mergo v0.3.13 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/klauspost/cpuid/v2 v2.2.6 // indirect
	github.com/lufia/plan9stats v0.0.0-20230110061619-bbe2e5e100de // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/minio/md5-simd v1.1.2 // indirect
	github.com/minio/sha256-simd v1.0.1 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/mitchellh/pointerstructure v1.2.1 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/moby/term v0.0.0-20201216013528-df9cb8a40635 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.2 // indirect
	github.com/opencontainers/runc v1.1.12 // indirect
	github.com/philhofer/fwd v1.1.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/power-devops/perfstat v0.0.0-20221212215047-62379fc7944b // indirect
	github.com/prometheus/client_model v0.4.0 // indirect
	github.com/prometheus/common v0.44.0 // indirect
	github.com/prometheus/procfs v0.9.0 // indirect
	github.com/prometheus/prom2json v1.3.3 // indirect
	github.com/rs/xid v1.5.0 // indirect
	github.com/safchain/ethtool v0.3.0 // indirect
	github.com/secure-io/sio-go v0.3.1 // indirect
	github.com/shirou/gopsutil/v3 v3.23.12 // indirect
	github.com/shoenig/go-m1cpu v0.1.6 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/tinylib/msgp v1.1.8 // indirect
	github.com/tklauser/go-sysconf v0.3.12 // indirect
	github.com/tklauser/numcpus v0.6.1 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20180127040702-4e3ac2762d5f // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xeipuuv/gojsonschema v1.2.0 // indirect
	github.com/yusufpapurcu/wmi v1.2.3 // indirect
	golang.org/x/crypto v0.22.0 // indirect
	golang.org/x/mod v0.9.0 // indirect
	golang.org/x/net v0.24.0 // indirect
	golang.org/x/sync v0.5.0 // indirect
	golang.org/x/sys v0.19.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	golang.org/x/tools v0.7.0 // indirect
	google.golang.org/genproto v0.0.0-20240116215550-a9fa1716bcac // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240125205218-1f4bbc51befe // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240125205218-1f4bbc51befe // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
