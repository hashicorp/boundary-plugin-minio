// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package testing

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/require"
)

const (
	rootUsername   = "minio"
	rootPassword   = "minio1234567890"
	apiAddress     = ":9000"
	consoleAddress = ":9090"
)

var (
	defaultRepository = "minio/minio"
	defaultVersion    = "latest"
)

type MinioServer struct {
	// RootUsername is the root account username on the MinIO instance.
	RootUsername string
	// RootPassword is the root account password on the MinIO instance.
	RootPassword string
	// ServiceAccountAccessKeyId is the access key id for the default service
	// account created in NewMinioServer.
	ServiceAccountAccessKeyId string
	// ServiceAccountSecretAccessKey is the secret access key for the default
	// service account created in NewMinioServer.
	ServiceAccountSecretAccessKey string
	// ApiAddr is the MinIO S3 API address.
	ApiAddr string
	// Client is a MinIO SDK client, created with the default service account
	// credentials.
	Client *minio.Client
	// AdminClient is a Madmin client created with the root account credentials.
	AdminClient *madmin.AdminClient
}

type Option func(testing.TB, *options)

type options struct {
	repository  string
	version     string
	skipCleanup bool
}

func defaultOptions(t testing.TB) options {
	return options{
		repository:  defaultRepository,
		version:     defaultVersion,
		skipCleanup: false,
	}
}

func getOptions(t testing.TB, opts ...Option) options {
	t.Helper()
	do := defaultOptions(t)
	for _, o := range opts {
		o(t, &do)
	}
	return do
}

// WithRepository controls the MinIO docker image used.
func WithRepository(r string) Option {
	return func(t testing.TB, o *options) {
		t.Helper()
		o.repository = r
	}
}

// WithVersion controls the MinIO docker image version used.
func WithVersion(v string) Option {
	return func(t testing.TB, o *options) {
		t.Helper()
		o.version = v
	}
}

// WithSkipCleanup controls whether the MinIO instance gets destroyed after the
// test is run. If this option is passed, the instance will not be destroyed.
func WithSkipCleanup(s bool) Option {
	return func(t testing.TB, o *options) {
		t.Helper()
		o.skipCleanup = s
	}
}

func init() {
	mirror := os.Getenv("DOCKER_MIRROR")
	if mirror != "" {
		defaultRepository = strings.Join([]string{mirror, defaultRepository}, "/")
	}
}

// NewMinioServer uses docker to create a MinIO instance, ensures the instance
// is healthy, then creates a service account before returning a MinIOServer
// object, which contains the SDK client for API operations and the Madmin
// client for MinIO Admin operations.
func NewMinioServer(t testing.TB, inOpts ...Option) *MinioServer {
	pool, err := dockertest.NewPool("")
	require.NoError(t, err)

	opts := getOptions(t, inOpts...)

	dockerOptions := &dockertest.RunOptions{
		Repository: opts.repository,
		Tag:        opts.version,
		Env: []string{
			fmt.Sprintf("%s=%s", "MINIO_ROOT_USER", rootUsername),
			fmt.Sprintf("%s=%s", "MINIO_ROOT_PASSWORD", rootPassword),
			fmt.Sprintf("%s=%s", "MINIO_ADDRESS", apiAddress),
			fmt.Sprintf("%s=%s", "MINIO_CONSOLE_ADDRESS", consoleAddress),
			fmt.Sprintf("%s=%s", "MINIO_VOLUMES", "/mnt/data"),
		},
		Cmd: []string{"server"},
	}

	r, err := pool.RunWithOptions(dockerOptions)
	require.NoError(t, err)
	if !opts.skipCleanup {
		t.Cleanup(func() { r.Close() })
	}

	server := &MinioServer{
		RootUsername: rootUsername,
		RootPassword: rootPassword,
		ApiAddr:      fmt.Sprintf("localhost:%s", r.GetPort("9000/tcp")),
	}

	// Ensure the instance is healthy.
	healthCl, err := minio.New(server.ApiAddr, &minio.Options{Secure: false})
	require.NoError(t, err)
	cancelFn, err := healthCl.HealthCheck(time.Second)
	require.NoError(t, err)

	healthy := false
	retries := 5
	interval := 500 * time.Millisecond
	for i := 0; i < retries; i++ {
		if healthCl.IsOnline() {
			healthy = true
			break
		}
		<-time.After(interval)
	}
	if !healthy {
		cancelFn()
		require.NoError(t, fmt.Errorf("minio instance not healthy after %s", time.Duration(retries)*interval))
		return nil
	}

	// Create service account.
	acl, err := madmin.NewWithOptions(server.ApiAddr, &madmin.Options{
		Creds:  credentials.NewStaticV4(server.RootUsername, server.RootPassword, ""),
		Secure: false,
	})
	require.NoError(t, err)
	server.AdminClient = acl

	creds, err := acl.AddServiceAccount(context.Background(), madmin.AddServiceAccountReq{
		Name:        "Boundary MinIO Plugin Test",
		Description: "MinIO credentials for Boundary MinIO plugin testing",
	})
	require.NoError(t, err)
	server.ServiceAccountAccessKeyId = creds.AccessKey
	server.ServiceAccountSecretAccessKey = creds.SecretKey

	cl, err := minio.New(server.ApiAddr, &minio.Options{
		Creds:  credentials.NewStaticV4(creds.AccessKey, creds.SecretKey, ""),
		Secure: false,
	})
	require.NoError(t, err)
	server.Client = cl

	return server
}
