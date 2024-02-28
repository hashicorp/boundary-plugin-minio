// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package storage

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	internaltest "github.com/hashicorp/boundary-plugin-minio/internal/testing"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/storagebuckets"
	"github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
)

var (
	policyDenyPutObject = []byte(`{
		"Statement": [
			{
				"Action": [ "s3:*" ],
				"Effect": "Allow",
				"Resource": "arn:aws:s3:::*"
			},
			{
				"Action": [ "s3:PutObject" ],
				"Effect": "Deny",
				"Resource": "arn:aws:s3:::*"
			},
			{
				"Action": [
					"admin:CreateServiceAccount",
					"admin:RemoveServiceAccount"
				],
				"Effect": "Allow"
			}
		],
		"Version": "2012-10-17"
	}`)
	policyDenyStatObject = []byte(`{
		"Statement": [
			{
				"Action": [ "s3:*" ],
				"Effect": "Allow",
				"Resource": "arn:aws:s3:::*"
			},
			{
				"Action": [
					"s3:GetObject",
					"s3:GetObjectVersion",
					"s3:GetObjectAttributes",
					"s3:GetObjectVersionAttributes"
				],
				"Effect": "Deny",
				"Resource": "arn:aws:s3:::*"
			},
			{
				"Action": [
					"admin:CreateServiceAccount",
					"admin:RemoveServiceAccount"
				],
				"Effect": "Allow"
			}
		],
		"Version": "2012-10-17"
	}`)
	policyDenyListBucket = []byte(`{
		"Statement": [
			{
				"Action": [ "s3:*" ],
				"Effect": "Allow",
				"Resource": "arn:aws:s3:::*"
			},
			{
				"Action": [ "s3:ListBucket" ],
				"Effect": "Deny",
				"Resource": "arn:aws:s3:::*"
			},
			{
				"Action": [
					"admin:CreateServiceAccount",
					"admin:RemoveServiceAccount"
				],
				"Effect": "Allow"
			}
		],
		"Version": "2012-10-17"
	}`)
	policyDenyDeleteObject = []byte(`{
		"Statement": [
			{
				"Action": [ "s3:*" ],
				"Effect": "Allow",
				"Resource": "arn:aws:s3:::*"
			},
			{
				"Action": [ "s3:DeleteObject" ],
				"Effect": "Deny",
				"Resource": "arn:aws:s3:::*"
			},
			{
				"Action": [
					"admin:CreateServiceAccount",
					"admin:RemoveServiceAccount"
				],
				"Effect": "Allow"
			}
		],
		"Version": "2012-10-17"
	}`)
)

func TestOnCreateStorageBucket(t *testing.T) {
	ctx := context.Background()
	server := internaltest.NewMinioServer(t)

	bucketName := "test-bucket"
	err := server.Client.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{})
	require.NoError(t, err)

	tests := []struct {
		name      string
		minioClFn func(t *testing.T) *minio.Client
		req       *plugin.OnCreateStorageBucketRequest
		expRsp    *plugin.OnCreateStorageBucketResponse
		expErrMsg string
	}{
		{
			name:      "nilBucket",
			req:       &plugin.OnCreateStorageBucketRequest{Bucket: nil},
			expErrMsg: "no storage bucket information found",
		},
		{
			name: "noBucketName",
			req: &plugin.OnCreateStorageBucketRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "",
				},
			},
			expErrMsg: "storage bucket name is required",
		},
		{
			name: "badStorageAttributes",
			req: &plugin.OnCreateStorageBucketRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: bucketName,
				},
			},
			expErrMsg: "empty attributes input",
		},
		{
			name: "badStorageSecrets",
			req: &plugin.OnCreateStorageBucketRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: bucketName,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstEndpointUrl: structpb.NewStringValue("http://foo"),
						},
					},
				},
			},
			expErrMsg: "empty secrets input",
		},
		{
			name: "usingNonServiceAccount",
			req: &plugin.OnCreateStorageBucketRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: bucketName,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstEndpointUrl: structpb.NewStringValue("http://" + server.ApiAddr),
						},
					},
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstAccessKeyId:     structpb.NewStringValue(server.RootUsername),
							ConstSecretAccessKey: structpb.NewStringValue(server.RootPassword),
						},
					},
				},
			},
			expErrMsg: "The specified service account is not found (Specified service account does not exist)",
		},
		{
			name: "dryRunFail",
			req: &plugin.OnCreateStorageBucketRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: bucketName,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstEndpointUrl: structpb.NewStringValue("http://" + server.ApiAddr),
						},
					},
					Secrets: &structpb.Struct{
						Fields: func() map[string]*structpb.Value {
							creds, err := server.AdminClient.AddServiceAccount(ctx, madmin.AddServiceAccountReq{
								Policy: policyDenyPutObject,
							})
							require.NoError(t, err)

							return map[string]*structpb.Value{
								ConstAccessKeyId:     structpb.NewStringValue(creds.AccessKey),
								ConstSecretAccessKey: structpb.NewStringValue(creds.SecretKey),
							}
						}(),
					},
				},
			},
			expErrMsg: "failed to verify provided minio environment: failed to put object",
		},
		{
			name: "success",
			req: &plugin.OnCreateStorageBucketRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: bucketName,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstEndpointUrl: structpb.NewStringValue("http://" + server.ApiAddr),
						},
					},
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstAccessKeyId:     structpb.NewStringValue(server.ServiceAccountAccessKeyId),
							ConstSecretAccessKey: structpb.NewStringValue(server.ServiceAccountSecretAccessKey),
						},
					},
				},
			},
			expRsp: &plugin.OnCreateStorageBucketResponse{
				Persisted: &storagebuckets.StorageBucketPersisted{
					Data: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstAccessKeyId:     structpb.NewStringValue(server.ServiceAccountAccessKeyId),
							ConstSecretAccessKey: structpb.NewStringValue(server.ServiceAccountSecretAccessKey),
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sp := new(StoragePlugin)
			rsp, err := sp.OnCreateStorageBucket(ctx, tt.req)
			if tt.expErrMsg != "" {
				require.ErrorContains(t, err, tt.expErrMsg)
				require.Nil(t, rsp)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, rsp)
			require.Empty(t, cmp.Diff(tt.expRsp, rsp, protocmp.Transform()))
		})
	}
}

func TestOnUpdateStorageBucket(t *testing.T) {}

func TestOnDeleteStorageBucket(t *testing.T) {
	sp := new(StoragePlugin)
	rsp, err := sp.OnDeleteStorageBucket(context.Background(), &plugin.OnDeleteStorageBucketRequest{})
	require.NoError(t, err)
	require.NotNil(t, rsp)
}

func TestValidatePermissions(t *testing.T) {
	ctx := context.Background()
	server := internaltest.NewMinioServer(t)

	bucketName := "test-bucket"
	err := server.Client.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{})
	require.NoError(t, err)

	tests := []struct {
		name      string
		minioClFn func(t *testing.T) *minio.Client
		req       *plugin.ValidatePermissionsRequest
		expErrMsg string
	}{
		{
			name:      "nilBucket",
			req:       &plugin.ValidatePermissionsRequest{Bucket: nil},
			expErrMsg: "no storage bucket information found",
		},
		{
			name: "noBucketName",
			req: &plugin.ValidatePermissionsRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "",
				},
			},
			expErrMsg: "storage bucket name is required",
		},
		{
			name: "badStorageAttributes",
			req: &plugin.ValidatePermissionsRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: bucketName,
				},
			},
			expErrMsg: "empty attributes input",
		},
		{
			name: "badStorageSecrets",
			req: &plugin.ValidatePermissionsRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: bucketName,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstEndpointUrl: structpb.NewStringValue("http://foo"),
						},
					},
				},
			},
			expErrMsg: "empty secrets input",
		},
		{
			name: "usingNonServiceAccount",
			req: &plugin.ValidatePermissionsRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: bucketName,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstEndpointUrl: structpb.NewStringValue("http://" + server.ApiAddr),
						},
					},
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstAccessKeyId:     structpb.NewStringValue(server.RootUsername),
							ConstSecretAccessKey: structpb.NewStringValue(server.RootPassword),
						},
					},
				},
			},
			expErrMsg: "The specified service account is not found (Specified service account does not exist)",
		},
		{
			name: "dryRunFail",
			req: &plugin.ValidatePermissionsRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: bucketName,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstEndpointUrl: structpb.NewStringValue("http://" + server.ApiAddr),
						},
					},
					Secrets: &structpb.Struct{
						Fields: func() map[string]*structpb.Value {
							creds, err := server.AdminClient.AddServiceAccount(ctx, madmin.AddServiceAccountReq{
								Policy: policyDenyPutObject,
							})
							require.NoError(t, err)

							return map[string]*structpb.Value{
								ConstAccessKeyId:     structpb.NewStringValue(creds.AccessKey),
								ConstSecretAccessKey: structpb.NewStringValue(creds.SecretKey),
							}
						}(),
					},
				},
			},
			expErrMsg: "failed to verify provided minio environment: failed to put object",
		},
		{
			name: "success",
			req: &plugin.ValidatePermissionsRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: bucketName,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstEndpointUrl: structpb.NewStringValue("http://" + server.ApiAddr),
						},
					},
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstAccessKeyId:     structpb.NewStringValue(server.ServiceAccountAccessKeyId),
							ConstSecretAccessKey: structpb.NewStringValue(server.ServiceAccountSecretAccessKey),
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sp := new(StoragePlugin)
			rsp, err := sp.ValidatePermissions(ctx, tt.req)
			if tt.expErrMsg != "" {
				require.ErrorContains(t, err, tt.expErrMsg)
				require.Nil(t, rsp)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, rsp)
		})
	}
}

func TestHeadObject(t *testing.T) {}

func TestGetObject(t *testing.T) {}

func TestPutObject(t *testing.T) {}

func TestDeleteObjects(t *testing.T) {}

func TestDryRun(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name         string
		minioClFn    func(t *testing.T, s *internaltest.MinioServer) *minio.Client
		makeBucketFn func(t *testing.T, cl *minio.Client) string
		// This test verifies that each message in the err slice is contained in
		// the error string, effectively &&-ing the checks together.
		expErrMsgs []string
	}{
		{
			name:         "bucketNotExists",
			makeBucketFn: func(t *testing.T, cl *minio.Client) string { return "unknownbucket" },
			expErrMsgs:   []string{"The specified bucket does not exist"},
		},
		{
			name: "putObjectFail",
			minioClFn: func(t *testing.T, s *internaltest.MinioServer) *minio.Client {
				creds, err := s.AdminClient.AddServiceAccount(ctx, madmin.AddServiceAccountReq{
					Policy: policyDenyPutObject,
				})
				require.NoError(t, err)

				cl, err := minio.New(s.ApiAddr, &minio.Options{
					Creds:  credentials.NewStaticV4(creds.AccessKey, creds.SecretKey, ""),
					Secure: false,
				})
				require.NoError(t, err)

				return cl
			},
			makeBucketFn: func(t *testing.T, cl *minio.Client) string {
				bucketName := "testdryrun-putobjectfail"
				err := cl.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{})
				require.NoError(t, err)

				return bucketName
			},
			expErrMsgs: []string{
				"failed to put object",
				"Access Denied",
			},
		},
		{
			name: "statObjectFail",
			minioClFn: func(t *testing.T, s *internaltest.MinioServer) *minio.Client {
				creds, err := s.AdminClient.AddServiceAccount(ctx, madmin.AddServiceAccountReq{
					Policy: policyDenyStatObject,
				})
				require.NoError(t, err)

				cl, err := minio.New(s.ApiAddr, &minio.Options{
					Creds:  credentials.NewStaticV4(creds.AccessKey, creds.SecretKey, ""),
					Secure: false,
				})
				require.NoError(t, err)

				return cl
			},
			makeBucketFn: func(t *testing.T, cl *minio.Client) string {
				bucketName := "testdryrun-statobjectfail"
				err := cl.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{})
				require.NoError(t, err)

				return bucketName
			},
			expErrMsgs: []string{
				"failed to stat object",
				"Access Denied",
			},
		},
		{
			name: "listObjectsFail",
			minioClFn: func(t *testing.T, s *internaltest.MinioServer) *minio.Client {
				creds, err := s.AdminClient.AddServiceAccount(ctx, madmin.AddServiceAccountReq{
					Policy: policyDenyListBucket,
				})
				require.NoError(t, err)

				cl, err := minio.New(s.ApiAddr, &minio.Options{
					Creds:  credentials.NewStaticV4(creds.AccessKey, creds.SecretKey, ""),
					Secure: false,
				})
				require.NoError(t, err)

				return cl
			},
			makeBucketFn: func(t *testing.T, cl *minio.Client) string {
				bucketName := "testdryrun-listobjectsfail"
				err := cl.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{})
				require.NoError(t, err)

				return bucketName
			},
			expErrMsgs: []string{
				"failed to list objects in bucket",
				"Access Denied",
			},
		},
		{
			name: "removeObjectFail",
			minioClFn: func(t *testing.T, s *internaltest.MinioServer) *minio.Client {
				creds, err := s.AdminClient.AddServiceAccount(ctx, madmin.AddServiceAccountReq{
					Policy: policyDenyDeleteObject,
				})
				require.NoError(t, err)

				cl, err := minio.New(s.ApiAddr, &minio.Options{
					Creds:  credentials.NewStaticV4(creds.AccessKey, creds.SecretKey, ""),
					Secure: false,
				})
				require.NoError(t, err)

				return cl
			},
			makeBucketFn: func(t *testing.T, cl *minio.Client) string {
				bucketName := "testdryrun-removeobjectfail"
				err := cl.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{})
				require.NoError(t, err)

				return bucketName
			},
			expErrMsgs: []string{
				"failed to remove object",
				"Access Denied",
			},
		},
		{
			name: "success",
			makeBucketFn: func(t *testing.T, cl *minio.Client) string {
				bucketName := "testdryrun-success"
				err := cl.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{})
				require.NoError(t, err)
				return bucketName
			},
		},
	}

	server := internaltest.NewMinioServer(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			minioClient := server.Client
			if tt.minioClFn != nil {
				minioClient = tt.minioClFn(t, server)
			}

			bucketName := tt.makeBucketFn(t, minioClient)
			err := dryRun(ctx, minioClient, &storagebuckets.StorageBucket{
				BucketName: bucketName,
			})
			if len(tt.expErrMsgs) > 0 {
				for _, errMsg := range tt.expErrMsgs {
					require.ErrorContains(t, err, errMsg)
				}
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestEnsureServiceAccount(t *testing.T) {
	tests := []struct {
		name      string
		saFunc    func(s *internaltest.MinioServer) (*StorageAttributes, *StorageSecrets)
		expErrMsg string
	}{
		{
			name: "nonServiceAccount",
			saFunc: func(s *internaltest.MinioServer) (*StorageAttributes, *StorageSecrets) {
				return &StorageAttributes{
						EndpointUrl: s.ApiAddr,
						UseSSL:      false,
					}, &StorageSecrets{
						AccessKeyId:     s.RootUsername,
						SecretAccessKey: s.RootPassword,
					}
			},
			expErrMsg: "The specified service account is not found (Specified service account does not exist)",
		},
		{
			name: "serviceAccount",
			saFunc: func(s *internaltest.MinioServer) (*StorageAttributes, *StorageSecrets) {
				return &StorageAttributes{
						EndpointUrl: s.ApiAddr,
						UseSSL:      false,
					}, &StorageSecrets{
						AccessKeyId:     s.ServiceAccountAccessKeyId,
						SecretAccessKey: s.ServiceAccountSecretAccessKey,
					}
			},
		},
	}

	server := internaltest.NewMinioServer(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sa, sec := tt.saFunc(server)
			err := ensureServiceAccount(context.Background(), sa, sec)
			if tt.expErrMsg != "" {
				require.ErrorContains(t, err, tt.expErrMsg)
				return
			}
			require.NoError(t, err)
		})
	}
}
