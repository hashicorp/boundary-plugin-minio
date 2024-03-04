// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package storage

import (
	"bytes"
	"context"
	"fmt"
	"path"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	internaltest "github.com/hashicorp/boundary-plugin-minio/internal/testing"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/storagebuckets"
	"github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

func TestOnUpdateStorageBucket(t *testing.T) {
	ctx := context.Background()
	server := internaltest.NewMinioServer(t)

	bucketName := "test-bucket"
	require.NoError(t, server.Client.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{}))

	tests := []struct {
		name     string
		req      *plugin.OnUpdateStorageBucketRequest
		expected *plugin.OnUpdateStorageBucketResponse
		err      string
		errCode  codes.Code
	}{
		{
			name:    "nilNewBucket",
			req:     &plugin.OnUpdateStorageBucketRequest{},
			err:     "new bucket is required",
			errCode: codes.InvalidArgument,
		},
		{
			name: "emptyNewBucketName",
			req: &plugin.OnUpdateStorageBucketRequest{
				NewBucket: &storagebuckets.StorageBucket{},
			},
			err:     "new bucketName is required",
			errCode: codes.InvalidArgument,
		},
		{
			name: "nilCurrentBucket",
			req: &plugin.OnUpdateStorageBucketRequest{
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
				},
			},
			err:     "current bucket is required",
			errCode: codes.InvalidArgument,
		},
		{
			name: "nilCurrentBucketAttributes",
			req: &plugin.OnUpdateStorageBucketRequest{
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
				},
				CurrentBucket: &storagebuckets.StorageBucket{},
			},
			err:     "empty attributes input",
			errCode: codes.InvalidArgument,
		},
		{
			name: "nilNewBucketAttributes",
			req: &plugin.OnUpdateStorageBucketRequest{
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Secrets:    new(structpb.Struct),
				},
				CurrentBucket: &storagebuckets.StorageBucket{
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstEndpointUrl: structpb.NewStringValue("http://" + server.ApiAddr),
						},
					},
				},
			},
			err:     "empty attributes input",
			errCode: codes.InvalidArgument,
		},
		{
			name: "nilNewBucketSecrets",
			req: &plugin.OnUpdateStorageBucketRequest{
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstEndpointUrl: structpb.NewStringValue("http://" + server.ApiAddr),
						},
					},
				},
				CurrentBucket: &storagebuckets.StorageBucket{
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstEndpointUrl: structpb.NewStringValue("http://" + server.ApiAddr),
						},
					},
				},
			},
			err:     "empty secrets input",
			errCode: codes.InvalidArgument,
		},
		{
			name: "errorReadingAttributes",
			req: &plugin.OnUpdateStorageBucketRequest{
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Secrets:    new(structpb.Struct),
					Attributes: new(structpb.Struct),
				},
				CurrentBucket: &storagebuckets.StorageBucket{
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstEndpointUrl: structpb.NewStringValue("http://" + server.ApiAddr),
						},
					},
				},
			},
			err:     "empty attributes input",
			errCode: codes.InvalidArgument,
		},
		{
			name: "errorReadingSecrets",
			req: &plugin.OnUpdateStorageBucketRequest{
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstEndpointUrl: structpb.NewStringValue("http://" + server.ApiAddr),
						},
					},
					Secrets: new(structpb.Struct),
				},
				CurrentBucket: &storagebuckets.StorageBucket{
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstEndpointUrl: structpb.NewStringValue("http://" + server.ApiAddr),
						},
					},
				},
			},
			err:     "empty secrets input",
			errCode: codes.InvalidArgument,
		},
		{
			name: "invalidBucketNameUpdate",
			req: &plugin.OnUpdateStorageBucketRequest{
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
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
				CurrentBucket: &storagebuckets.StorageBucket{
					BucketName: "foo2",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstEndpointUrl: structpb.NewStringValue("http://" + server.ApiAddr),
						},
					},
				},
			},
			err:     "cannot update attribute BucketName",
			errCode: codes.InvalidArgument,
		},
		{
			name: "invalidBucketPrefixUpdate",
			req: &plugin.OnUpdateStorageBucketRequest{
				NewBucket: &storagebuckets.StorageBucket{
					BucketName:   "foo",
					BucketPrefix: "foo",
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
				CurrentBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstEndpointUrl: structpb.NewStringValue("http://" + server.ApiAddr),
						},
					},
				},
			},
			err:     "cannot update attribute BucketPrefix",
			errCode: codes.InvalidArgument,
		},
		{
			name: "invalidRegionUpdate",
			req: &plugin.OnUpdateStorageBucketRequest{
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstEndpointUrl: structpb.NewStringValue("http://" + server.ApiAddr),
							"region":         structpb.NewStringValue("a region"),
						},
					},
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstAccessKeyId:     structpb.NewStringValue(server.ServiceAccountAccessKeyId),
							ConstSecretAccessKey: structpb.NewStringValue(server.ServiceAccountSecretAccessKey),
						},
					},
				},
				CurrentBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstEndpointUrl: structpb.NewStringValue("http://" + server.ApiAddr),
						},
					},
				},
			},
			err:     "cannot update attribute Region",
			errCode: codes.InvalidArgument,
		},
		{
			name: "invalidEndpointUrlUpdate",
			req: &plugin.OnUpdateStorageBucketRequest{
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstEndpointUrl: structpb.NewStringValue("http://localhost:9000"),
						},
					},
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstAccessKeyId:     structpb.NewStringValue(server.ServiceAccountAccessKeyId),
							ConstSecretAccessKey: structpb.NewStringValue(server.ServiceAccountSecretAccessKey),
						},
					},
				},
				CurrentBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstEndpointUrl: structpb.NewStringValue("http://" + server.ApiAddr),
						},
					},
				},
			},
			err:     "cannot update attribute EndpointUrl",
			errCode: codes.InvalidArgument,
		},
		{
			name: "usingNonServiceAccount",
			req: &plugin.OnUpdateStorageBucketRequest{
				NewBucket: &storagebuckets.StorageBucket{
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
				CurrentBucket: &storagebuckets.StorageBucket{
					BucketName: bucketName,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstEndpointUrl: structpb.NewStringValue("http://" + server.ApiAddr),
						},
					},
				},
				Persisted: &storagebuckets.StorageBucketPersisted{
					Data: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstAccessKeyId:     structpb.NewStringValue(server.RootUsername),
							ConstSecretAccessKey: structpb.NewStringValue(server.RootPassword),
						},
					},
				},
			},
			err:     "The specified service account is not found (Specified service account does not exist)",
			errCode: codes.InvalidArgument,
		},
		{
			name: "dryRunFail",
			req: &plugin.OnUpdateStorageBucketRequest{
				NewBucket: &storagebuckets.StorageBucket{
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
				CurrentBucket: &storagebuckets.StorageBucket{
					BucketName: bucketName,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstEndpointUrl: structpb.NewStringValue("http://" + server.ApiAddr),
						},
					},
				},
				Persisted: &storagebuckets.StorageBucketPersisted{
					Data: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstAccessKeyId:     structpb.NewStringValue(server.RootUsername),
							ConstSecretAccessKey: structpb.NewStringValue(server.RootPassword),
						},
					},
				},
			},
			err:     "failed to verify provided minio environment: failed to put object",
			errCode: codes.InvalidArgument,
		},
		{
			name: "success",
			req: &plugin.OnUpdateStorageBucketRequest{
				NewBucket: &storagebuckets.StorageBucket{
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
				CurrentBucket: &storagebuckets.StorageBucket{
					BucketName: bucketName,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstEndpointUrl: structpb.NewStringValue("http://" + server.ApiAddr),
						},
					},
				},
				Persisted: &storagebuckets.StorageBucketPersisted{
					Data: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstAccessKeyId:     structpb.NewStringValue(server.RootUsername),
							ConstSecretAccessKey: structpb.NewStringValue(server.RootPassword),
						},
					},
				},
			},
			expected: &plugin.OnUpdateStorageBucketResponse{
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
			require := require.New(t)
			sp := new(StoragePlugin)
			res, err := sp.OnUpdateStorageBucket(ctx, tt.req)
			if tt.err != "" {
				require.ErrorContains(err, tt.err)
				require.Equal(tt.errCode.String(), status.Code(err).String())
				require.Nil(res)
				return
			}

			require.NoError(err)
			require.NotNil(res)
			require.EqualValues(tt.expected, res)
		})
	}
}

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

func TestHeadObject(t *testing.T) {
	ctx := context.Background()
	server := internaltest.NewMinioServer(t)

	bucketName := "test-bucket"
	err := server.Client.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{})
	require.NoError(t, err)

	objectKey := fmt.Sprintf("test-head-object-%s", uuid.New().String())
	rd := bytes.NewReader([]byte("test-head-object-contents"))
	_, err = server.Client.PutObject(ctx, bucketName, objectKey, rd, rd.Size(), minio.PutObjectOptions{})
	require.NoError(t, err)

	bucketPrefix := "prefix"
	rd2 := bytes.NewReader([]byte("test-head-object-contents"))
	_, err = server.Client.PutObject(ctx, bucketName, path.Join(bucketPrefix, objectKey), rd2, rd2.Size(), minio.PutObjectOptions{})
	require.NoError(t, err)

	tests := []struct {
		name      string
		req       *plugin.HeadObjectRequest
		expErrMsg string
	}{
		{
			name:      "nilBucket",
			req:       &plugin.HeadObjectRequest{Bucket: nil},
			expErrMsg: "no storage bucket information found",
		},
		{
			name: "emptyBucket",
			req: &plugin.HeadObjectRequest{
				Bucket: &storagebuckets.StorageBucket{},
			},
			expErrMsg: "storage bucket name is required",
		},
		{
			name: "emptyObjectKey",
			req: &plugin.HeadObjectRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: bucketName,
				},
				Key: "",
			},
			expErrMsg: "object key is required",
		},
		{
			name: "badStorageAttributes",
			req: &plugin.HeadObjectRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: bucketName,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint_url": structpb.NewStringValue("foo"),
						},
					},
				},
				Key: "object-key",
			},
			expErrMsg: "attributes.endpoint_url.format: unknown protocol, should be http:// or https://",
		},
		{
			name: "badStorageSecrets",
			req: &plugin.HeadObjectRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: bucketName,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint_url": structpb.NewStringValue("http://foo"),
						},
					},
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"access_key_id": structpb.NewStringValue("foo"),
						},
					},
				},
				Key: "object-key",
			},
			expErrMsg: "secrets.secret_access_key: missing required value \"secret_access_key\"",
		},
		{
			name: "statObjectFail",
			req: &plugin.HeadObjectRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: bucketName,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstEndpointUrl: structpb.NewStringValue("http://localhost:1"),
						},
					},
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstAccessKeyId:     structpb.NewStringValue("foo"),
							ConstSecretAccessKey: structpb.NewStringValue("bar"),
						},
					},
				},
				Key: "object-key",
			},
			expErrMsg: "failed to stat object",
		},
		{
			name: "nonExistantKey",
			req: &plugin.HeadObjectRequest{
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
				Key: "doesnt-exist",
			},
			expErrMsg: "failed to stat object: The specified key does not exist.",
		},
		{
			name: "success",
			req: &plugin.HeadObjectRequest{
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
				Key: objectKey,
			},
		},
		{
			name: "successWithBucketPrefix",
			req: &plugin.HeadObjectRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName:   bucketName,
					BucketPrefix: bucketPrefix,
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
				Key: objectKey,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sp := new(StoragePlugin)
			rsp, err := sp.HeadObject(ctx, tt.req)
			if tt.expErrMsg != "" {
				require.ErrorContains(t, err, tt.expErrMsg)
				require.Nil(t, rsp)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, rsp)
			require.Equal(t, rd.Size(), rsp.GetContentLength())
			require.NotEmpty(t, rsp.GetLastModified().AsTime())
		})
	}
}

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
