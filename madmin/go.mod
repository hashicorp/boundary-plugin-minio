module github.com/hashicorp/boundary-plugin-minio/madmin

go 1.23
toolchain go1.24.1

require (
	github.com/minio/minio-go/v7 v7.0.83
	github.com/secure-io/sio-go v0.3.1
	golang.org/x/crypto v0.35.0
)

require golang.org/x/sys v0.30.0 // indirect
