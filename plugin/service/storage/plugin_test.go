// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package storage

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	internaltest "github.com/hashicorp/boundary-plugin-minio/internal/testing"
	"github.com/hashicorp/boundary-plugin-minio/internal/values"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/storagebuckets"
	"github.com/hashicorp/boundary/sdk/pbs/plugin"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
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

type getObjectServerMock struct {
	grpc.ServerStream
	ctx           context.Context
	sendErr       error
	clientCtxDone bool
	chunks        []*pb.GetObjectResponse
}

// Context returns the object server's context.
func (s *getObjectServerMock) Context() context.Context {
	if s.ctx == nil {
		return context.Background()
	}
	return s.ctx
}

// Send streams a response message to the client.
func (g *getObjectServerMock) Send(rsp *pb.GetObjectResponse) error {
	if g.sendErr != nil {
		return g.sendErr
	}
	if rsp == nil {
		return fmt.Errorf("getobject stream mock: nil response")
	}
	if g.chunks == nil {
		g.chunks = []*pb.GetObjectResponse{}
	}
	g.chunks = append(g.chunks, rsp)
	if g.clientCtxDone {
		ctx, cancel := context.WithCancel(g.ctx)
		g.ctx = ctx
		cancel()
	}
	return nil
}

// Recv streams a response message from the server.
func (g *getObjectServerMock) Recv() (*pb.GetObjectResponse, error) {
	if g.chunks == nil {
		return nil, fmt.Errorf("getobject stream mock: nil chunks")
	}
	if len(g.chunks) == 0 {
		return nil, io.EOF
	}

	// Pop a chunk off and return it.
	chunk := g.chunks[0]
	g.chunks = g.chunks[1:]
	return chunk, nil
}

func TestOnCreateStorageBucket(t *testing.T) {
	ctx := context.Background()
	server := internaltest.NewMinioServer(t)

	bucketName := "test-bucket"
	err := server.Client.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{})
	require.NoError(t, err)

	tests := []struct {
		name                string
		req                 *plugin.OnCreateStorageBucketRequest
		expRsp              *plugin.OnCreateStorageBucketResponse
		expCredRotation     bool
		expErrMsg           string
		expectedPermissions *pb.Permissions
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
			name: "dryRunFail",
			req: &plugin.OnCreateStorageBucketRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: bucketName,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstEndpointUrl:               structpb.NewStringValue("http://" + server.ApiAddr),
							ConstDisableCredentialRotation: structpb.NewBoolValue(true),
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
			expectedPermissions: &pb.Permissions{
				Write:  &pb.Permission{State: pb.StateType_STATE_TYPE_ERROR, ErrorDetails: "Access Denied."},
				Read:   &pb.Permission{State: pb.StateType_STATE_TYPE_UNKNOWN, ErrorDetails: "The specified key does not exist."},
				Delete: &pb.Permission{State: pb.StateType_STATE_TYPE_OK, ErrorDetails: ""},
			},
		},
		{
			name: "credRotationFail",
			req: func() *plugin.OnCreateStorageBucketRequest {
				creds, err := server.AdminClient.AddServiceAccount(ctx, madmin.AddServiceAccountReq{
					Policy: json.RawMessage(`
					{
						"Statement": [
							{
								"Action": [
									"admin:CreateServiceAccount",
									"admin:RemoveServiceAccount"
								],
								"Effect": "Deny"
							}
						],
						"Version": "2012-10-17"
					}
					`),
				})
				require.NoError(t, err)

				return &plugin.OnCreateStorageBucketRequest{
					Bucket: &storagebuckets.StorageBucket{
						BucketName: bucketName,
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								ConstEndpointUrl:               structpb.NewStringValue("http://" + server.ApiAddr),
								ConstDisableCredentialRotation: structpb.NewBoolValue(false),
							},
						},
						Secrets: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								ConstAccessKeyId:     structpb.NewStringValue(creds.AccessKey),
								ConstSecretAccessKey: structpb.NewStringValue(creds.SecretKey),
							},
						},
					},
				}
			}(),
			expErrMsg: "failed to rotate minio credentials: failed to create new minio service account: Access Denied",
		},
		{
			name: "credRotationFailNoSvcAcct",
			req: func() *plugin.OnCreateStorageBucketRequest {
				return &plugin.OnCreateStorageBucketRequest{
					Bucket: &storagebuckets.StorageBucket{
						BucketName: bucketName,
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								ConstEndpointUrl:               structpb.NewStringValue("http://" + server.ApiAddr),
								ConstDisableCredentialRotation: structpb.NewBoolValue(false),
							},
						},
						Secrets: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								ConstAccessKeyId:     structpb.NewStringValue(server.RootUsername),
								ConstSecretAccessKey: structpb.NewStringValue(server.RootPassword),
							},
						},
					},
				}
			}(),
			expErrMsg: "The specified service account is not found (Specified service account does not exist)",
		},
		{
			name: "successNonServiceAccount",
			req: &plugin.OnCreateStorageBucketRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: bucketName,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstEndpointUrl:               structpb.NewStringValue("http://" + server.ApiAddr),
							ConstDisableCredentialRotation: structpb.NewBoolValue(true),
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
			expRsp: &plugin.OnCreateStorageBucketResponse{
				Persisted: &storagebuckets.StorageBucketPersisted{
					Data: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstAccessKeyId:     structpb.NewStringValue(server.RootUsername),
							ConstSecretAccessKey: structpb.NewStringValue(server.RootPassword),
						},
					},
				},
			},
		},
		{
			name: "successNoRotation",
			req: &plugin.OnCreateStorageBucketRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: bucketName,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstEndpointUrl:               structpb.NewStringValue("http://" + server.ApiAddr),
							ConstDisableCredentialRotation: structpb.NewBoolValue(true),
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
		{
			name: "successWithRotation",
			req: func() *plugin.OnCreateStorageBucketRequest {
				creds, err := server.AdminClient.AddServiceAccount(ctx, madmin.AddServiceAccountReq{})
				require.NoError(t, err)

				return &plugin.OnCreateStorageBucketRequest{
					Bucket: &storagebuckets.StorageBucket{
						BucketName: bucketName,
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								ConstEndpointUrl:               structpb.NewStringValue("http://" + server.ApiAddr),
								ConstDisableCredentialRotation: structpb.NewBoolValue(false),
							},
						},
						Secrets: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								ConstAccessKeyId:     structpb.NewStringValue(creds.AccessKey),
								ConstSecretAccessKey: structpb.NewStringValue(creds.SecretKey),
							},
						},
					},
				}
			}(),
			expRsp: &plugin.OnCreateStorageBucketResponse{
				Persisted: &storagebuckets.StorageBucketPersisted{
					Data: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							// Determined during test runtime.
						},
					},
				},
			},
			expCredRotation: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sp := new(StoragePlugin)
			rsp, err := sp.OnCreateStorageBucket(ctx, tt.req)
			if tt.expErrMsg != "" {
				require.ErrorContains(t, err, tt.expErrMsg)
				require.Nil(t, rsp)

				// Check the permission error.
				if tt.expectedPermissions != nil {
					st, ok := status.FromError(err)
					require.True(t, ok)
					var permission *pb.StorageBucketCredentialState
					for _, detail := range st.Details() {
						if errDetail, ok := detail.(*pb.StorageBucketCredentialState); ok {
							permission = errDetail
							break
						}
					}
					require.NotNil(t, permission)

					assert.Equal(t, tt.expectedPermissions.GetWrite().GetState(), permission.GetState().GetWrite().GetState())
					assert.Equal(t, tt.expectedPermissions.GetRead().GetState(), permission.GetState().GetRead().GetState())
					assert.Equal(t, tt.expectedPermissions.GetDelete().GetState(), permission.GetState().GetDelete().GetState())

					assert.Contains(t, tt.expectedPermissions.GetWrite().GetErrorDetails(), permission.GetState().GetWrite().GetErrorDetails())
					assert.Contains(t, tt.expectedPermissions.GetRead().GetErrorDetails(), permission.GetState().GetRead().GetErrorDetails())
					assert.Contains(t, tt.expectedPermissions.GetDelete().GetErrorDetails(), permission.GetState().GetDelete().GetErrorDetails())
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, rsp)

			if tt.expCredRotation {
				inAccessKeyId, err := values.GetStringValue(tt.req.Bucket.GetSecrets(), ConstAccessKeyId, true)
				require.NoError(t, err)

				inSecretAccessKey, err := values.GetStringValue(tt.req.Bucket.GetSecrets(), ConstSecretAccessKey, true)
				require.NoError(t, err)

				rspAccessKeyId, err := values.GetStringValue(rsp.GetPersisted().GetData(), ConstAccessKeyId, true)
				require.NoError(t, err)
				require.NotEqual(t, inAccessKeyId, rspAccessKeyId)

				rspSecretAccessKey, err := values.GetStringValue(rsp.GetPersisted().GetData(), ConstSecretAccessKey, true)
				require.NoError(t, err)
				require.NotEqual(t, inSecretAccessKey, rspSecretAccessKey)

				rspLastRotatedTime, err := values.GetTimeValue(rsp.GetPersisted().GetData(), ConstLastRotatedTime)
				require.NoError(t, err)
				require.False(t, rspLastRotatedTime.IsZero())

				_, err = server.AdminClient.InfoServiceAccount(ctx, inAccessKeyId)
				require.ErrorContains(t, err, "specified service account is not found")

				_, err = server.AdminClient.InfoServiceAccount(ctx, rspAccessKeyId)
				require.NoError(t, err)
			} else {
				require.Empty(t, cmp.Diff(tt.expRsp, rsp, protocmp.Transform(),
					cmp.FilterPath(func(p cmp.Path) bool {
						step, ok := p.Last().(cmp.MapIndex)
						return ok && step.Key().String() == ConstLastRotatedTime
					}, cmp.Ignore()),
				))
			}
		})
	}
}

func TestOnUpdateStorageBucket(t *testing.T) {
	ctx := context.Background()
	server := internaltest.NewMinioServer(t)

	bucketName := "test-bucket"
	require.NoError(t, server.Client.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{}))

	tests := []struct {
		name                string
		req                 *plugin.OnUpdateStorageBucketRequest
		expected            *plugin.OnUpdateStorageBucketResponse
		err                 string
		expectedPermissions *pb.Permissions
		errCode             codes.Code
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
			name: "errorReadingNewBucketSecrets",
			req: &plugin.OnUpdateStorageBucketRequest{
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstEndpointUrl: structpb.NewStringValue("http://" + server.ApiAddr),
						},
					},
					Secrets: &structpb.Struct{},
				},
				CurrentBucket: &storagebuckets.StorageBucket{
					BucketName: "foo",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstEndpointUrl: structpb.NewStringValue("http://" + server.ApiAddr),
						},
					},
				},
				Persisted: &storagebuckets.StorageBucketPersisted{
					Data: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstAccessKeyId:     structpb.NewStringValue("foo"),
							ConstSecretAccessKey: structpb.NewStringValue("bar"),
						},
					},
				},
			},
			err:     "empty secrets input",
			errCode: codes.InvalidArgument,
		},
		{
			name: "errorReadingNewBucketAttributes",
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
			name: "errorReadingPersistedSecrets",
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
				Persisted: &storagebuckets.StorageBucketPersisted{
					Data: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstAccessKeyId:     structpb.NewStringValue(server.ServiceAccountAccessKeyId),
							ConstSecretAccessKey: structpb.NewStringValue(server.ServiceAccountSecretAccessKey),
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
				Persisted: &storagebuckets.StorageBucketPersisted{
					Data: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstAccessKeyId:     structpb.NewStringValue(server.ServiceAccountAccessKeyId),
							ConstSecretAccessKey: structpb.NewStringValue(server.ServiceAccountSecretAccessKey),
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
				Persisted: &storagebuckets.StorageBucketPersisted{
					Data: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstAccessKeyId:     structpb.NewStringValue(server.ServiceAccountAccessKeyId),
							ConstSecretAccessKey: structpb.NewStringValue(server.ServiceAccountSecretAccessKey),
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
				Persisted: &storagebuckets.StorageBucketPersisted{
					Data: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstAccessKeyId:     structpb.NewStringValue(server.ServiceAccountAccessKeyId),
							ConstSecretAccessKey: structpb.NewStringValue(server.ServiceAccountSecretAccessKey),
						},
					},
				},
			},
			err:     "cannot update attribute EndpointUrl",
			errCode: codes.InvalidArgument,
		},
		{
			name: "disableCredRotationOnRotatedCreds",
			req: &plugin.OnUpdateStorageBucketRequest{
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: bucketName,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstEndpointUrl:               structpb.NewStringValue("http://" + server.ApiAddr),
							ConstDisableCredentialRotation: structpb.NewBoolValue(true),
						},
					},
				},
				CurrentBucket: &storagebuckets.StorageBucket{
					BucketName: bucketName,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstEndpointUrl:               structpb.NewStringValue("http://" + server.ApiAddr),
							ConstDisableCredentialRotation: structpb.NewBoolValue(false),
						},
					},
				},
				Persisted: &storagebuckets.StorageBucketPersisted{
					Data: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstAccessKeyId:     structpb.NewStringValue(server.RootUsername),
							ConstSecretAccessKey: structpb.NewStringValue(server.RootPassword),
							ConstLastRotatedTime: structpb.NewStringValue(time.Now().Format(time.RFC3339Nano)),
						},
					},
				},
			},
			err:     "cannot disable rotation for already-rotated credentials",
			errCode: codes.InvalidArgument,
		},
		{
			name: "dryRunFail",
			req: &plugin.OnUpdateStorageBucketRequest{
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: bucketName,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstEndpointUrl:               structpb.NewStringValue("http://" + server.ApiAddr),
							ConstDisableCredentialRotation: structpb.NewBoolValue(true),
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
			expectedPermissions: &pb.Permissions{
				Write:  &pb.Permission{State: pb.StateType_STATE_TYPE_ERROR, ErrorDetails: "Access Denied."},
				Read:   &pb.Permission{State: pb.StateType_STATE_TYPE_UNKNOWN, ErrorDetails: "The specified key does not exist."},
				Delete: &pb.Permission{State: pb.StateType_STATE_TYPE_OK, ErrorDetails: ""},
			},
		},
		{
			name: "credRotationFailWithNewCreds",
			req: &plugin.OnUpdateStorageBucketRequest{
				CurrentBucket: &storagebuckets.StorageBucket{
					BucketName: bucketName,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstEndpointUrl:               structpb.NewStringValue("http://" + server.ApiAddr),
							ConstDisableCredentialRotation: structpb.NewBoolValue(false),
						},
					},
				},
				Persisted: &storagebuckets.StorageBucketPersisted{
					Data: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstAccessKeyId:     structpb.NewStringValue(server.ServiceAccountAccessKeyId),
							ConstSecretAccessKey: structpb.NewStringValue(server.ServiceAccountSecretAccessKey),
							ConstLastRotatedTime: structpb.NewStringValue(time.Now().Format(time.RFC3339Nano)),
						},
					},
				},
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: bucketName,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstEndpointUrl:               structpb.NewStringValue("http://" + server.ApiAddr),
							ConstDisableCredentialRotation: structpb.NewBoolValue(false),
						},
					},
					Secrets: func() *structpb.Struct {
						creds, err := server.AdminClient.AddServiceAccount(ctx, madmin.AddServiceAccountReq{
							Policy: json.RawMessage(`
							{
								"Statement": [
									{
										"Action": [
											"admin:CreateServiceAccount",
											"admin:RemoveServiceAccount"
										],
										"Effect": "Deny"
									}
								],
								"Version": "2012-10-17"
							}
							`),
						})
						require.NoError(t, err)

						return &structpb.Struct{
							Fields: map[string]*structpb.Value{
								ConstAccessKeyId:     structpb.NewStringValue(creds.AccessKey),
								ConstSecretAccessKey: structpb.NewStringValue(creds.SecretKey),
							},
						}
					}(),
				},
			},
			err:     "failed to rotate minio credentials: failed to create new minio service account: Access Denied",
			errCode: codes.InvalidArgument,
		},
		{
			name: "credRotationNoNewCreds",
			req: &plugin.OnUpdateStorageBucketRequest{
				CurrentBucket: &storagebuckets.StorageBucket{
					BucketName: bucketName,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstEndpointUrl:               structpb.NewStringValue("http://" + server.ApiAddr),
							ConstDisableCredentialRotation: structpb.NewBoolValue(true),
						},
					},
				},
				Persisted: &storagebuckets.StorageBucketPersisted{
					Data: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstAccessKeyId:     structpb.NewStringValue(server.ServiceAccountAccessKeyId),
							ConstSecretAccessKey: structpb.NewStringValue(server.ServiceAccountSecretAccessKey),
						},
					},
				},
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: bucketName,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstEndpointUrl:               structpb.NewStringValue("http://" + server.ApiAddr),
							ConstDisableCredentialRotation: structpb.NewBoolValue(false),
						},
					},
				},
			},
			err:     "credential rotation enabled with no new credentials provided",
			errCode: codes.InvalidArgument,
		},
		{
			name: "successUsingNonServiceAccount",
			req: &plugin.OnUpdateStorageBucketRequest{
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: bucketName,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstEndpointUrl:               structpb.NewStringValue("http://" + server.ApiAddr),
							ConstDisableCredentialRotation: structpb.NewBoolValue(true),
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
			expected: &plugin.OnUpdateStorageBucketResponse{
				Persisted: &storagebuckets.StorageBucketPersisted{
					Data: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstAccessKeyId:     structpb.NewStringValue(server.RootUsername),
							ConstSecretAccessKey: structpb.NewStringValue(server.RootPassword),
						},
					},
				},
			},
		},
		{
			name: "successNoRotation",
			req: &plugin.OnUpdateStorageBucketRequest{
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: bucketName,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstEndpointUrl:               structpb.NewStringValue("http://" + server.ApiAddr),
							ConstDisableCredentialRotation: structpb.NewBoolValue(true),
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

				// Check the permission error.
				if tt.expectedPermissions != nil {
					st, ok := status.FromError(err)
					require.True(ok)
					var permission *pb.StorageBucketCredentialState
					for _, detail := range st.Details() {
						if errDetail, ok := detail.(*pb.StorageBucketCredentialState); ok {
							permission = errDetail
							break
						}
					}
					require.NotNil(t, permission)

					assert.Equal(t, tt.expectedPermissions.GetWrite().GetState(), permission.GetState().GetWrite().GetState())
					assert.Equal(t, tt.expectedPermissions.GetRead().GetState(), permission.GetState().GetRead().GetState())
					assert.Equal(t, tt.expectedPermissions.GetDelete().GetState(), permission.GetState().GetDelete().GetState())

					assert.Contains(t, tt.expectedPermissions.GetWrite().GetErrorDetails(), permission.GetState().GetWrite().GetErrorDetails())
					assert.Contains(t, tt.expectedPermissions.GetRead().GetErrorDetails(), permission.GetState().GetRead().GetErrorDetails())
					assert.Contains(t, tt.expectedPermissions.GetDelete().GetErrorDetails(), permission.GetState().GetDelete().GetErrorDetails())
				}

				return
			}

			require.NoError(err)
			require.NotNil(res)
			require.Empty(cmp.Diff(tt.expected, res, protocmp.Transform(),
				cmp.FilterPath(func(p cmp.Path) bool {
					step, ok := p.Last().(cmp.MapIndex)
					return ok && step.Key().String() == ConstLastRotatedTime
				}, cmp.Ignore()),
			))
		})
	}
}

func TestOnUpdateStorageBucket_SuccessDisableCredRotationAndNewCreds(t *testing.T) {
	ctx := context.Background()
	server := internaltest.NewMinioServer(t)

	bucketName := "test"
	err := server.Client.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{})
	require.NoError(t, err)

	persistedCreds, err := server.AdminClient.AddServiceAccount(ctx, madmin.AddServiceAccountReq{})
	require.NoError(t, err)
	newCreds, err := server.AdminClient.AddServiceAccount(ctx, madmin.AddServiceAccountReq{})
	require.NoError(t, err)

	req := &plugin.OnUpdateStorageBucketRequest{
		CurrentBucket: &storagebuckets.StorageBucket{
			BucketName: bucketName,
			Attributes: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstEndpointUrl:               structpb.NewStringValue("http://" + server.ApiAddr),
					ConstDisableCredentialRotation: structpb.NewBoolValue(false),
				},
			},
		},
		Persisted: &storagebuckets.StorageBucketPersisted{
			Data: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstAccessKeyId:     structpb.NewStringValue(persistedCreds.AccessKey),
					ConstSecretAccessKey: structpb.NewStringValue(persistedCreds.SecretKey),
					ConstLastRotatedTime: structpb.NewStringValue(time.Now().Format(time.RFC3339Nano)),
				},
			},
		},
		NewBucket: &storagebuckets.StorageBucket{
			BucketName: bucketName,
			Attributes: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstEndpointUrl:               structpb.NewStringValue("http://" + server.ApiAddr),
					ConstDisableCredentialRotation: structpb.NewBoolValue(true),
				},
			},
			Secrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstAccessKeyId:     structpb.NewStringValue(newCreds.AccessKey),
					ConstSecretAccessKey: structpb.NewStringValue(newCreds.SecretKey),
				},
			},
		},
	}

	// `disable_cred_rotation` enabled -> disable and provide new creds.
	// This should delete the existing creds and set the new ones to be used
	// directly.
	sp := new(StoragePlugin)
	rsp, err := sp.OnUpdateStorageBucket(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, req)

	outAccessKeyId, err := values.GetStringValue(rsp.GetPersisted().GetData(), ConstAccessKeyId, true)
	require.NoError(t, err)
	require.Equal(t, newCreds.AccessKey, outAccessKeyId)

	outSecretAccessKey, err := values.GetStringValue(rsp.GetPersisted().GetData(), ConstSecretAccessKey, true)
	require.NoError(t, err)
	require.Equal(t, newCreds.SecretKey, outSecretAccessKey)

	lastRotated, err := values.GetTimeValue(rsp.GetPersisted().GetData(), ConstLastRotatedTime)
	require.NoError(t, err)
	require.True(t, lastRotated.IsZero())

	_, err = server.AdminClient.InfoServiceAccount(ctx, persistedCreds.AccessKey)
	require.ErrorContains(t, err, "specified service account is not found")

	_, err = server.AdminClient.InfoServiceAccount(ctx, newCreds.AccessKey)
	require.NoError(t, err)

	lsa, err := server.AdminClient.ListServiceAccounts(ctx, server.RootUsername)
	require.NoError(t, err)
	require.Len(t, lsa.Accounts, 2) // Creds in `server` + newCreds.
}

func TestOnUpdateStorageBucket_SuccessEnableCredRotationWithNewCreds(t *testing.T) {
	ctx := context.Background()
	server := internaltest.NewMinioServer(t)

	bucketName := "test"
	err := server.Client.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{})
	require.NoError(t, err)

	persistedCreds, err := server.AdminClient.AddServiceAccount(ctx, madmin.AddServiceAccountReq{})
	require.NoError(t, err)

	newCreds, err := server.AdminClient.AddServiceAccount(ctx, madmin.AddServiceAccountReq{})
	require.NoError(t, err)

	req := &plugin.OnUpdateStorageBucketRequest{
		CurrentBucket: &storagebuckets.StorageBucket{
			BucketName: bucketName,
			Attributes: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstEndpointUrl:               structpb.NewStringValue("http://" + server.ApiAddr),
					ConstDisableCredentialRotation: structpb.NewBoolValue(true),
				},
			},
		},
		Persisted: &storagebuckets.StorageBucketPersisted{
			Data: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstAccessKeyId:     structpb.NewStringValue(persistedCreds.AccessKey),
					ConstSecretAccessKey: structpb.NewStringValue(persistedCreds.SecretKey),
				},
			},
		},
		NewBucket: &storagebuckets.StorageBucket{
			BucketName: bucketName,
			Attributes: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstEndpointUrl:               structpb.NewStringValue("http://" + server.ApiAddr),
					ConstDisableCredentialRotation: structpb.NewBoolValue(false),
				},
			},
			Secrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstAccessKeyId:     structpb.NewStringValue(newCreds.AccessKey),
					ConstSecretAccessKey: structpb.NewStringValue(newCreds.SecretKey),
				},
			},
		},
	}

	// `disable_cred_rotation` disabled -> enable and provide new creds.
	// This should use the incoming credentials to generate new ones, then
	// delete the incoming ones and use the generated ones. The old persisted
	// credentials should not be deleted.
	sp := new(StoragePlugin)
	rsp, err := sp.OnUpdateStorageBucket(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, req)

	outAccessKeyId, err := values.GetStringValue(rsp.GetPersisted().GetData(), ConstAccessKeyId, true)
	require.NoError(t, err)
	require.NotEqual(t, persistedCreds.AccessKey, outAccessKeyId)
	require.NotEqual(t, newCreds.AccessKey, outAccessKeyId)

	outSecretAccessKey, err := values.GetStringValue(rsp.GetPersisted().GetData(), ConstSecretAccessKey, true)
	require.NoError(t, err)
	require.NotEqual(t, persistedCreds.SecretKey, outSecretAccessKey)
	require.NotEqual(t, newCreds.SecretKey, outSecretAccessKey)

	lastRotated, err := values.GetTimeValue(rsp.GetPersisted().GetData(), ConstLastRotatedTime)
	require.NoError(t, err)
	require.False(t, lastRotated.IsZero())

	_, err = server.AdminClient.InfoServiceAccount(ctx, persistedCreds.AccessKey)
	require.NoError(t, err)

	_, err = server.AdminClient.InfoServiceAccount(ctx, newCreds.AccessKey)
	require.ErrorContains(t, err, "specified service account is not found")

	_, err = server.AdminClient.InfoServiceAccount(ctx, outAccessKeyId)
	require.NoError(t, err)

	lsa, err := server.AdminClient.ListServiceAccounts(ctx, server.RootUsername)
	require.NoError(t, err)
	require.Len(t, lsa.Accounts, 3) // Creds in `server` + persistedCreds + newly rotated creds.
}

func TestOnUpdateStorageBucket_SuccessNoCredRotationChangeDisabledNewCreds(t *testing.T) {
	ctx := context.Background()
	server := internaltest.NewMinioServer(t)

	bucketName := "test"
	err := server.Client.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{})
	require.NoError(t, err)

	persistedCreds, err := server.AdminClient.AddServiceAccount(ctx, madmin.AddServiceAccountReq{})
	require.NoError(t, err)

	newCreds, err := server.AdminClient.AddServiceAccount(ctx, madmin.AddServiceAccountReq{})
	require.NoError(t, err)

	bucketAttrs := &structpb.Struct{
		Fields: map[string]*structpb.Value{
			ConstEndpointUrl:               structpb.NewStringValue("http://" + server.ApiAddr),
			ConstDisableCredentialRotation: structpb.NewBoolValue(true),
		},
	}
	req := &plugin.OnUpdateStorageBucketRequest{
		CurrentBucket: &storagebuckets.StorageBucket{
			BucketName: bucketName,
			Attributes: bucketAttrs,
		},
		Persisted: &storagebuckets.StorageBucketPersisted{
			Data: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstAccessKeyId:     structpb.NewStringValue(persistedCreds.AccessKey),
					ConstSecretAccessKey: structpb.NewStringValue(persistedCreds.SecretKey),
				},
			},
		},
		NewBucket: &storagebuckets.StorageBucket{
			BucketName: bucketName,
			Attributes: bucketAttrs,
			Secrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstAccessKeyId:     structpb.NewStringValue(newCreds.AccessKey),
					ConstSecretAccessKey: structpb.NewStringValue(newCreds.SecretKey),
				},
			},
		},
	}

	// Don't touch disable cred rotation (disabled) and provide new credentials.
	// Should set the new credentials to be used. The old persisted credentials
	// should not be deleted.
	sp := new(StoragePlugin)
	rsp, err := sp.OnUpdateStorageBucket(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, req)

	outAccessKeyId, err := values.GetStringValue(rsp.GetPersisted().GetData(), ConstAccessKeyId, true)
	require.NoError(t, err)
	require.Equal(t, newCreds.AccessKey, outAccessKeyId)

	outSecretAccessKey, err := values.GetStringValue(rsp.GetPersisted().GetData(), ConstSecretAccessKey, true)
	require.NoError(t, err)
	require.Equal(t, newCreds.SecretKey, outSecretAccessKey)

	_, err = server.AdminClient.InfoServiceAccount(ctx, persistedCreds.AccessKey)
	require.NoError(t, err)

	_, err = server.AdminClient.InfoServiceAccount(ctx, newCreds.AccessKey)
	require.NoError(t, err)

	lsa, err := server.AdminClient.ListServiceAccounts(ctx, server.RootUsername)
	require.NoError(t, err)
	require.Len(t, lsa.Accounts, 3) // Creds in `server` + persistedCreds + newCreds
}

func TestOnUpdateStorageBucket_SuccessNoCredRotationChangeEnabledNewCreds(t *testing.T) {
	ctx := context.Background()
	server := internaltest.NewMinioServer(t)

	bucketName := "test"
	err := server.Client.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{})
	require.NoError(t, err)

	persistedCreds, err := server.AdminClient.AddServiceAccount(ctx, madmin.AddServiceAccountReq{})
	require.NoError(t, err)

	newCreds, err := server.AdminClient.AddServiceAccount(ctx, madmin.AddServiceAccountReq{})
	require.NoError(t, err)

	bucketAttrs := &structpb.Struct{
		Fields: map[string]*structpb.Value{
			ConstEndpointUrl:               structpb.NewStringValue("http://" + server.ApiAddr),
			ConstDisableCredentialRotation: structpb.NewBoolValue(false),
		},
	}
	req := &plugin.OnUpdateStorageBucketRequest{
		CurrentBucket: &storagebuckets.StorageBucket{
			BucketName: bucketName,
			Attributes: bucketAttrs,
		},
		Persisted: &storagebuckets.StorageBucketPersisted{
			Data: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstAccessKeyId:     structpb.NewStringValue(persistedCreds.AccessKey),
					ConstSecretAccessKey: structpb.NewStringValue(persistedCreds.SecretKey),
					ConstLastRotatedTime: structpb.NewStringValue(time.Now().Format(time.RFC3339Nano)),
				},
			},
		},
		NewBucket: &storagebuckets.StorageBucket{
			BucketName: bucketName,
			Attributes: bucketAttrs,
			Secrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstAccessKeyId:     structpb.NewStringValue(newCreds.AccessKey),
					ConstSecretAccessKey: structpb.NewStringValue(newCreds.SecretKey),
				},
			},
		},
	}

	// Don't touch disable cred rotation (enabled) and provide new credentials.
	// Should use the incoming credentials to generate new ones, then delete the
	// incoming ones and use the generated ones. The old persisted credentials
	// should also be deleted.
	sp := new(StoragePlugin)
	rsp, err := sp.OnUpdateStorageBucket(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, req)

	outAccessKeyId, err := values.GetStringValue(rsp.GetPersisted().GetData(), ConstAccessKeyId, true)
	require.NoError(t, err)
	require.NotEqual(t, persistedCreds.AccessKey, outAccessKeyId)
	require.NotEqual(t, newCreds.AccessKey, outAccessKeyId)

	outSecretAccessKey, err := values.GetStringValue(rsp.GetPersisted().GetData(), ConstSecretAccessKey, true)
	require.NoError(t, err)
	require.NotEqual(t, persistedCreds.SecretKey, outSecretAccessKey)
	require.NotEqual(t, newCreds.SecretKey, outSecretAccessKey)

	lastRotated, err := values.GetTimeValue(rsp.GetPersisted().GetData(), ConstLastRotatedTime)
	require.NoError(t, err)
	require.False(t, lastRotated.IsZero())

	_, err = server.AdminClient.InfoServiceAccount(ctx, persistedCreds.AccessKey)
	require.ErrorContains(t, err, "specified service account is not found")

	_, err = server.AdminClient.InfoServiceAccount(ctx, newCreds.AccessKey)
	require.ErrorContains(t, err, "specified service account is not found")

	_, err = server.AdminClient.InfoServiceAccount(ctx, outAccessKeyId)
	require.NoError(t, err)

	lsa, err := server.AdminClient.ListServiceAccounts(ctx, server.RootUsername)
	require.NoError(t, err)
	require.Len(t, lsa.Accounts, 2) // Creds in `server` + newly rotated creds.
}

func TestOnCreateStorageBucket_NoChangesCredRotationDisabled(t *testing.T) {
	ctx := context.Background()
	server := internaltest.NewMinioServer(t)

	bucketName := "test"
	err := server.Client.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{})
	require.NoError(t, err)

	persistedCreds, err := server.AdminClient.AddServiceAccount(ctx, madmin.AddServiceAccountReq{})
	require.NoError(t, err)

	bucketAttrs := &structpb.Struct{
		Fields: map[string]*structpb.Value{
			ConstEndpointUrl:               structpb.NewStringValue("http://" + server.ApiAddr),
			ConstDisableCredentialRotation: structpb.NewBoolValue(true),
		},
	}
	req := &plugin.OnUpdateStorageBucketRequest{
		CurrentBucket: &storagebuckets.StorageBucket{
			BucketName: bucketName,
			Attributes: bucketAttrs,
		},
		Persisted: &storagebuckets.StorageBucketPersisted{
			Data: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstAccessKeyId:     structpb.NewStringValue(persistedCreds.AccessKey),
					ConstSecretAccessKey: structpb.NewStringValue(persistedCreds.SecretKey),
					ConstLastRotatedTime: structpb.NewStringValue(time.Time{}.Format(time.RFC3339Nano)),
				},
			},
		},
		NewBucket: &storagebuckets.StorageBucket{
			BucketName: bucketName,
			Attributes: bucketAttrs,
		},
	}

	// No changes with credential rotation disabled. This should change nothing.
	sp := new(StoragePlugin)
	rsp, err := sp.OnUpdateStorageBucket(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, req)

	require.Empty(t, cmp.Diff(req.GetPersisted(), rsp.GetPersisted(), protocmp.Transform()))

	_, err = server.AdminClient.InfoServiceAccount(ctx, persistedCreds.AccessKey)
	require.NoError(t, err)

	lsa, err := server.AdminClient.ListServiceAccounts(ctx, server.RootUsername)
	require.NoError(t, err)
	require.Len(t, lsa.Accounts, 2) // Creds in `server` + persistedCreds
}

func TestOnCreateStorageBucket_NoChangesCredRotationEnabled(t *testing.T) {
	ctx := context.Background()
	server := internaltest.NewMinioServer(t)

	bucketName := "test"
	err := server.Client.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{})
	require.NoError(t, err)

	persistedCreds, err := server.AdminClient.AddServiceAccount(ctx, madmin.AddServiceAccountReq{})
	require.NoError(t, err)

	bucketAttrs := &structpb.Struct{
		Fields: map[string]*structpb.Value{
			ConstEndpointUrl:               structpb.NewStringValue("http://" + server.ApiAddr),
			ConstDisableCredentialRotation: structpb.NewBoolValue(false),
		},
	}
	req := &plugin.OnUpdateStorageBucketRequest{
		CurrentBucket: &storagebuckets.StorageBucket{
			BucketName: bucketName,
			Attributes: bucketAttrs,
		},
		Persisted: &storagebuckets.StorageBucketPersisted{
			Data: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstAccessKeyId:     structpb.NewStringValue(persistedCreds.AccessKey),
					ConstSecretAccessKey: structpb.NewStringValue(persistedCreds.SecretKey),
					ConstLastRotatedTime: structpb.NewStringValue(time.Now().Format(time.RFC3339Nano)),
				},
			},
		},
		NewBucket: &storagebuckets.StorageBucket{
			BucketName: bucketName,
			Attributes: bucketAttrs,
		},
	}

	// No changes with credential rotation enabled. This should change nothing.
	sp := new(StoragePlugin)
	rsp, err := sp.OnUpdateStorageBucket(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, req)

	require.Empty(t, cmp.Diff(req.GetPersisted(), rsp.GetPersisted(), protocmp.Transform()))

	_, err = server.AdminClient.InfoServiceAccount(ctx, persistedCreds.AccessKey)
	require.NoError(t, err)

	lsa, err := server.AdminClient.ListServiceAccounts(ctx, server.RootUsername)
	require.NoError(t, err)
	require.Len(t, lsa.Accounts, 2) // Creds in `server` + persistedCreds
}

func TestOnDeleteStorageBucket(t *testing.T) {
	ctx := context.Background()
	server := internaltest.NewMinioServer(t)

	tests := []struct {
		name            string
		in              *pb.OnDeleteStorageBucketRequest
		expCredsDeleted bool
		expErrMsg       string
	}{
		{
			name: "nilBucket",
			in: &pb.OnDeleteStorageBucketRequest{
				Bucket: nil,
			},
			expErrMsg: "no storage bucket information found",
		},
		{
			name: "nilPersistedSecrets",
			in: &pb.OnDeleteStorageBucketRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "test",
				},
				Persisted: nil,
			},
			expErrMsg: "empty secrets input",
		},
		{
			name: "rotationNilAttributes",
			in: &pb.OnDeleteStorageBucketRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "test",
					Attributes: nil,
				},
				Persisted: &storagebuckets.StorageBucketPersisted{
					Data: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstAccessKeyId:     structpb.NewStringValue("foo"),
							ConstSecretAccessKey: structpb.NewStringValue("bar"),
							ConstLastRotatedTime: structpb.NewStringValue(time.Now().Format(time.RFC3339Nano)),
						},
					},
				},
			},
			expErrMsg: "empty attributes input",
		},
		{
			name: "rotationFail",
			in: &pb.OnDeleteStorageBucketRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "test",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstEndpointUrl:               structpb.NewStringValue("http://" + server.ApiAddr),
							ConstDisableCredentialRotation: structpb.NewBoolValue(true),
						},
					},
				},
				Persisted: &storagebuckets.StorageBucketPersisted{
					Data: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							ConstAccessKeyId:     structpb.NewStringValue("foo"),
							ConstSecretAccessKey: structpb.NewStringValue("bar"),
							ConstLastRotatedTime: structpb.NewStringValue(time.Now().Format(time.RFC3339Nano)),
						},
					},
				},
			},
			expErrMsg: "failed to delete minio service account",
		},
		{
			name: "successNoRotation",
			in: func() *pb.OnDeleteStorageBucketRequest {
				creds, err := server.AdminClient.AddServiceAccount(ctx, madmin.AddServiceAccountReq{})
				require.NoError(t, err)

				return &pb.OnDeleteStorageBucketRequest{
					Bucket: &storagebuckets.StorageBucket{
						BucketName: "test",
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								ConstEndpointUrl:               structpb.NewStringValue("http://" + server.ApiAddr),
								ConstDisableCredentialRotation: structpb.NewBoolValue(true),
							},
						},
					},
					Persisted: &storagebuckets.StorageBucketPersisted{
						Data: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								ConstAccessKeyId:     structpb.NewStringValue(creds.AccessKey),
								ConstSecretAccessKey: structpb.NewStringValue(creds.SecretKey),
								ConstLastRotatedTime: structpb.NewStringValue(time.Time{}.Format(time.RFC3339Nano)),
							},
						},
					},
				}
			}(),
			expCredsDeleted: false,
		},
		{
			name: "successWithRotation",
			in: func() *pb.OnDeleteStorageBucketRequest {
				creds, err := server.AdminClient.AddServiceAccount(ctx, madmin.AddServiceAccountReq{})
				require.NoError(t, err)

				return &pb.OnDeleteStorageBucketRequest{
					Bucket: &storagebuckets.StorageBucket{
						BucketName: "test",
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								ConstEndpointUrl:               structpb.NewStringValue("http://" + server.ApiAddr),
								ConstDisableCredentialRotation: structpb.NewBoolValue(false),
							},
						},
					},
					Persisted: &storagebuckets.StorageBucketPersisted{
						Data: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								ConstAccessKeyId:     structpb.NewStringValue(creds.AccessKey),
								ConstSecretAccessKey: structpb.NewStringValue(creds.SecretKey),
								ConstLastRotatedTime: structpb.NewStringValue(time.Now().Format(time.RFC3339Nano)),
							},
						},
					},
				}
			}(),
			expCredsDeleted: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sp := new(StoragePlugin)
			rsp, err := sp.OnDeleteStorageBucket(ctx, tt.in)
			if tt.expErrMsg != "" {
				require.ErrorContains(t, err, tt.expErrMsg)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, rsp)

			accessKeyIn, err := values.GetStringValue(tt.in.GetPersisted().GetData(), ConstAccessKeyId, true)
			require.NoError(t, err)

			_, err = server.AdminClient.InfoServiceAccount(ctx, accessKeyIn)
			if tt.expCredsDeleted {
				require.ErrorContains(t, err, "specified service account is not found")
			} else {
				require.NoError(t, err)
			}
		})
	}
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
			name: "rotatedNonServiceAccount",
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
							ConstLastRotatedTime: structpb.NewStringValue(time.Now().Format(time.RFC3339Nano)),
						},
					},
				},
			},
			expErrMsg: "The specified service account is not found (Specified service account does not exist)",
		},
		{
			name: "successNonServiceAccount",
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
			expErrMsg: "specified object does not exist",
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

func TestGetObject(t *testing.T) {
	ctx := context.Background()
	server := internaltest.NewMinioServer(t)

	bucketName := "test-bucket"
	err := server.Client.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{})
	require.NoError(t, err)

	tests := []struct {
		name        string
		in          func(t *testing.T) (*plugin.GetObjectRequest, []byte)
		mockSendErr error
		mockCtxDone bool
		expErrMsg   string
		expErrCode  codes.Code
	}{
		{
			name: "nilBucket",
			in: func(t *testing.T) (*pb.GetObjectRequest, []byte) {
				return &pb.GetObjectRequest{Bucket: nil}, []byte{}
			},
			expErrMsg:  "no storage bucket information found",
			expErrCode: codes.InvalidArgument,
		},
		{
			name: "noBucketName",
			in: func(t *testing.T) (*pb.GetObjectRequest, []byte) {
				return &pb.GetObjectRequest{
					Bucket: &storagebuckets.StorageBucket{BucketName: ""},
				}, []byte{}
			},
			expErrMsg:  "storage bucket name is required",
			expErrCode: codes.InvalidArgument,
		},
		{
			name: "emptyObjectKey",
			in: func(t *testing.T) (*pb.GetObjectRequest, []byte) {
				return &pb.GetObjectRequest{
					Bucket: &storagebuckets.StorageBucket{
						BucketName: bucketName,
					},
					Key: "",
				}, []byte{}
			},
			expErrMsg:  "object key is required",
			expErrCode: codes.InvalidArgument,
		},
		{
			name: "badStorageAttributes",
			in: func(t *testing.T) (*pb.GetObjectRequest, []byte) {
				return &pb.GetObjectRequest{
					Bucket: &storagebuckets.StorageBucket{
						BucketName: bucketName,
					},
					Key: "object-name",
				}, []byte{}
			},
			expErrMsg:  "empty attributes input",
			expErrCode: codes.InvalidArgument,
		},
		{
			name: "badStorageSecrets",
			in: func(t *testing.T) (*pb.GetObjectRequest, []byte) {
				return &pb.GetObjectRequest{
					Bucket: &storagebuckets.StorageBucket{
						BucketName: bucketName,
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								ConstEndpointUrl: structpb.NewStringValue("http://foo"),
							},
						},
					},
					Key: "object-name",
				}, []byte{}
			},
			expErrMsg:  "empty secrets input",
			expErrCode: codes.InvalidArgument,
		},
		{
			name: "getObjectErr",
			in: func(t *testing.T) (*pb.GetObjectRequest, []byte) {
				return &pb.GetObjectRequest{
					Bucket: &storagebuckets.StorageBucket{
						BucketName: "invalid..bucket..name",
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
					Key: "object-name",
				}, []byte{}
			},
			expErrMsg:  "failed to get object: Bucket name contains invalid characters",
			expErrCode: codes.Unknown,
		},
		{
			name: "readObjectErr",
			in: func(t *testing.T) (*pb.GetObjectRequest, []byte) {
				return &pb.GetObjectRequest{
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
					Key: "object-name",
				}, []byte{}
			},
			expErrMsg:  "failed to read chunk from minio object",
			expErrCode: codes.Unknown,
		},
		{
			name: "objectDoesntExist",
			in: func(t *testing.T) (*pb.GetObjectRequest, []byte) {
				return &pb.GetObjectRequest{
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
					Key: "object-name",
				}, []byte{}
			},
			expErrMsg:  "failed to read chunk from minio object: The specified key does not exist.",
			expErrCode: codes.Unknown,
		},
		{
			name: "objServerSendErr",
			in: func(t *testing.T) (*pb.GetObjectRequest, []byte) {
				objName := uuid.New().String()
				rd := bytes.NewReader([]byte("test"))
				_, err := server.Client.PutObject(ctx, bucketName, objName, rd, rd.Size(), minio.PutObjectOptions{})
				require.NoError(t, err)

				return &pb.GetObjectRequest{
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
					Key: objName,
				}, []byte{}
			},
			mockSendErr: fmt.Errorf("oops error"),
			expErrMsg:   "failed to send chunk to client: oops error",
			expErrCode:  codes.Unknown,
		},
		{
			name: "contextCancellation",
			in: func(t *testing.T) (*pb.GetObjectRequest, []byte) {
				objName := uuid.New().String()

				data := []byte{}
				for i := 0; i < 8192; i += len(objName) {
					data = append(data, []byte(objName)...)
				}
				rd := bytes.NewReader(data)
				_, err := server.Client.PutObject(ctx, bucketName, objName, rd, rd.Size(), minio.PutObjectOptions{})
				require.NoError(t, err)

				return &pb.GetObjectRequest{
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
					Key:       objName,
					ChunkSize: 2048,
				}, data
			},
			mockCtxDone: true,
			expErrMsg:   "server context done while streaming: context canceled",
			expErrCode:  codes.Canceled,
		},
		{
			name: "successSingleChunk",
			in: func(t *testing.T) (*pb.GetObjectRequest, []byte) {
				objName := uuid.New().String()

				data := []byte{}
				for i := 0; i < 8192; i += len(objName) {
					data = append(data, []byte(objName)...)
				}
				rd := bytes.NewReader(data)
				_, err := server.Client.PutObject(ctx, bucketName, objName, rd, rd.Size(), minio.PutObjectOptions{})
				require.NoError(t, err)

				return &pb.GetObjectRequest{
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
					Key:       objName,
					ChunkSize: 16384,
				}, data
			},
		},
		{
			name: "successCustomPrefix",
			in: func(t *testing.T) (*pb.GetObjectRequest, []byte) {
				objName := uuid.New().String()

				data := []byte{}
				for i := 0; i < 8192; i += len(objName) {
					data = append(data, []byte(objName)...)
				}
				rd := bytes.NewReader(data)

				prefix := "prefix"
				_, err := server.Client.PutObject(ctx, bucketName, path.Join(prefix, objName), rd, rd.Size(), minio.PutObjectOptions{})
				require.NoError(t, err)

				return &pb.GetObjectRequest{
					Bucket: &storagebuckets.StorageBucket{
						BucketName:   bucketName,
						BucketPrefix: prefix,
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
					Key: objName,
				}, data
			},
		},
		{
			name: "successMultipleChunksDefaultChunkSize",
			in: func(t *testing.T) (*pb.GetObjectRequest, []byte) {
				objName := uuid.New().String()

				data := []byte{}
				for i := 0; i < 102_400; i += len(objName) {
					data = append(data, []byte(objName)...)
				}
				rd := bytes.NewReader(data)
				_, err := server.Client.PutObject(ctx, bucketName, objName, rd, rd.Size(), minio.PutObjectOptions{})
				require.NoError(t, err)

				return &pb.GetObjectRequest{
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
					Key: objName,
				}, data
			},
		},
		{
			name: "successMultipleChunksCustomChunkSize",
			in: func(t *testing.T) (*pb.GetObjectRequest, []byte) {
				objName := uuid.New().String()

				data := []byte{}
				for i := 0; i < 10_420; i += len(objName) {
					data = append(data, []byte(objName)...)
				}
				rd := bytes.NewReader(data)
				_, err := server.Client.PutObject(ctx, bucketName, objName, rd, rd.Size(), minio.PutObjectOptions{})
				require.NoError(t, err)

				return &pb.GetObjectRequest{
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
					Key:       objName,
					ChunkSize: 4096,
				}, data
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objServer := &getObjectServerMock{
				ctx:           ctx,
				clientCtxDone: tt.mockCtxDone,
				sendErr:       tt.mockSendErr,
			}

			req, expFileBytes := tt.in(t)
			sp := new(StoragePlugin)
			err := sp.GetObject(req, objServer)
			if tt.expErrMsg != "" {
				require.ErrorContains(t, err, tt.expErrMsg)
				require.Equal(t, tt.expErrCode.String(), status.Code(err).String())
				return
			}
			require.NoError(t, err)

			expChunkSize := defaultGetObjectChunkSize
			if req.ChunkSize > 0 {
				expChunkSize = req.ChunkSize
			}

			bb := bytes.NewBuffer([]byte{})
			for {
				rsp, err := objServer.Recv()
				if err == io.EOF {
					break
				}
				require.NoError(t, err)
				require.LessOrEqual(t, uint32(len(rsp.GetFileChunk())), expChunkSize)

				n, err := bb.Write(rsp.GetFileChunk())
				require.NoError(t, err)
				require.EqualValues(t, len(rsp.GetFileChunk()), n)
			}

			require.Equal(t, expFileBytes, bb.Bytes())
		})
	}
}

func TestPutObject(t *testing.T) {
	td := t.TempDir()

	dirPath := func(p string) string {
		return path.Join(td, p)
	}

	ctx := context.Background()
	server := internaltest.NewMinioServer(t)

	bucketName := "test-bucket"
	require.NoError(t, server.Client.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{}))

	cases := []struct {
		name    string
		req     *plugin.PutObjectRequest
		setup   func(*plugin.PutObjectRequest) ([]byte, error)
		err     string
		errCode codes.Code
	}{
		{
			name:    "nilRequest",
			err:     "no storage bucket information found",
			errCode: codes.InvalidArgument,
		},
		{
			name:    "nilBucket",
			req:     &plugin.PutObjectRequest{Bucket: nil},
			err:     "no storage bucket information found",
			errCode: codes.InvalidArgument,
		},
		{
			name: "emptyBucket",
			req: &plugin.PutObjectRequest{
				Bucket: &storagebuckets.StorageBucket{},
			},
			err:     "storage bucket name is required",
			errCode: codes.InvalidArgument,
		},
		{
			name: "emptyObjectKey",
			req: &plugin.PutObjectRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: bucketName,
				},
				Key: "",
			},
			err:     "object key is required",
			errCode: codes.InvalidArgument,
		},
		{
			name: "emptyFilePath",
			req: &plugin.PutObjectRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: bucketName,
				},
				Key:  "test-key",
				Path: "",
			},
			err:     "path is required",
			errCode: codes.InvalidArgument,
		},
		{
			name: "badStorageAttributes",
			req: &plugin.PutObjectRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: bucketName,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint_url": structpb.NewStringValue("foo"),
						},
					},
				},
				Key:  "object-key",
				Path: "file-path",
			},
			err:     "attributes.endpoint_url.format: unknown protocol, should be http:// or https://",
			errCode: codes.InvalidArgument,
		},
		{
			name: "badStorageSecrets",
			req: &plugin.PutObjectRequest{
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
				Key:  "object-key",
				Path: "file-path",
			},
			err:     "secrets.secret_access_key: missing required value \"secret_access_key\"",
			errCode: codes.InvalidArgument,
		},
		{
			name: "emptyFile",
			req: &plugin.PutObjectRequest{
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
				Key:  "test-key",
				Path: dirPath("empty-test-file"),
			},
			setup: func(req *plugin.PutObjectRequest) ([]byte, error) {
				file, err := os.Create(req.Path)
				if err != nil {
					return nil, err
				}
				file.Close()
				return []byte{}, nil
			},
			err:     "file is empty",
			errCode: codes.InvalidArgument,
		},
		{
			name: "pathIsDir",
			req: &plugin.PutObjectRequest{
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
				Key:  "test-key",
				Path: td,
			},
			err:     "path is not a file",
			errCode: codes.InvalidArgument,
		},
		{
			name: "success",
			req: &plugin.PutObjectRequest{
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
				Key:  "test-key",
				Path: dirPath("test-file"),
			},
			setup: func(req *plugin.PutObjectRequest) ([]byte, error) {
				file, err := os.Create(req.Path)
				if err != nil {
					return nil, err
				}
				defer file.Close()

				data := []byte("test file data")

				if _, err = file.Write(data); err != nil {
					return nil, err
				}
				return data, nil
			},
		},
		{
			name: "successWithBucketPrefix",
			req: &plugin.PutObjectRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName:   bucketName,
					BucketPrefix: "test-prefix",
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
				Key:  "test-key-with-prefix",
				Path: dirPath("test-file-with-prefix"),
			},
			setup: func(req *plugin.PutObjectRequest) ([]byte, error) {
				file, err := os.Create(req.Path)
				if err != nil {
					return nil, err
				}
				defer file.Close()

				data := []byte("test file data for bucket with prefix")

				if _, err = file.Write(data); err != nil {
					return nil, err
				}
				return data, nil
			},
		},
		{
			name: "successWithLargeFile",
			req: &plugin.PutObjectRequest{
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
				Key:  "test-key-large-file",
				Path: dirPath("test-file-large"),
			},
			setup: func(req *plugin.PutObjectRequest) ([]byte, error) {
				file, err := os.Create(req.Path)
				if err != nil {
					return nil, err
				}
				defer file.Close()

				data := make([]byte, 30e6)
				n, err := rand.Reader.Read(data)
				if err != nil {
					return nil, err
				}
				if n != 30e6 {
					return nil, fmt.Errorf("did not read 30 million bytes")
				}

				if _, err = file.Write(data); err != nil {
					return nil, err
				}
				return data, nil
			},
		},
	}

	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			var checksum []byte
			var content []byte
			if tt.setup != nil {
				var err error
				content, err = tt.setup(tt.req)
				require.NoError(err)
				hash := sha256.New()
				_, err = hash.Write(content)
				require.NoError(err)
				checksum = hash.Sum(nil)
				require.NoError(err)
			}

			sp := new(StoragePlugin)
			res, err := sp.PutObject(ctx, tt.req)

			if tt.err != "" {
				assert.ErrorContains(err, tt.err)
				assert.Equal(tt.errCode.String(), status.Code(err).String())
				return
			}

			require.NotNil(res)
			assert.NotEmpty(res.GetChecksumSha_256())
			assert.Equal(checksum, res.ChecksumSha_256)

			// check the actual file content is the same
			cl, err := minio.New(server.ApiAddr, &minio.Options{
				Creds:  credentials.NewStaticV4(server.RootUsername, server.RootPassword, ""),
				Secure: false,
			})
			require.NoError(err)
			obj, err := cl.GetObject(ctx, bucketName, path.Join(tt.req.Bucket.GetBucketPrefix(), tt.req.GetKey()), minio.GetObjectOptions{})
			require.NoError(err)
			defer obj.Close()

			fmt.Printf("path: %v\n", tt.req.Path)
			contentLen := len(content)
			reader := bufio.NewReader(obj)
			buffer := make([]byte, contentLen)
			n, _ := reader.Read(buffer)
			// large files, for some reason, yield an EOF error when you read the full thing
			// require.NoError(err)

			assert.Equal(contentLen, n)
			assert.Equal(content, buffer)
		})
	}
}

func TestDeleteObjects(t *testing.T) {
	ctx := context.Background()
	server := internaltest.NewMinioServer(t)
	bucketName := "test-bucket"
	require.NoError(t, server.Client.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{}))

	cases := []struct {
		name     string
		req      *plugin.DeleteObjectsRequest
		setup    func(*minio.Client, *plugin.DeleteObjectsRequest) error
		expected uint32
		err      string
		errCode  codes.Code
	}{
		{
			name:    "nilRequest",
			err:     "no storage bucket information found",
			errCode: codes.InvalidArgument,
		},
		{
			name:    "nilBucket",
			req:     &plugin.DeleteObjectsRequest{Bucket: nil},
			err:     "no storage bucket information found",
			errCode: codes.InvalidArgument,
		},
		{
			name: "emptyBucket",
			req: &plugin.DeleteObjectsRequest{
				Bucket: &storagebuckets.StorageBucket{},
			},
			err:     "storage bucket name is required",
			errCode: codes.InvalidArgument,
		},
		{
			name: "emptyObjectKey",
			req: &plugin.DeleteObjectsRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: bucketName,
				},
				KeyPrefix: "",
			},
			err:     "key prefix is required",
			errCode: codes.InvalidArgument,
		},
		{
			name: "badStorageAttributes",
			req: &plugin.DeleteObjectsRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: bucketName,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint_url": structpb.NewStringValue("foo"),
						},
					},
				},
				KeyPrefix: "obj/path",
			},
			err:     "attributes.endpoint_url.format: unknown protocol, should be http:// or https://",
			errCode: codes.InvalidArgument,
		},
		{
			name: "badStorageSecrets",
			req: &plugin.DeleteObjectsRequest{
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
				KeyPrefix: "obj/path",
			},
			err:     "secrets.secret_access_key: missing required value \"secret_access_key\"",
			errCode: codes.InvalidArgument,
		},
		{
			name: "success",
			req: &plugin.DeleteObjectsRequest{
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
				KeyPrefix: "obj/path",
			},
			setup: func(cl *minio.Client, req *plugin.DeleteObjectsRequest) error {
				contents := "test file contents"
				file := bytes.NewBufferString(contents)
				if _, err := cl.PutObject(ctx, bucketName, req.KeyPrefix, file, int64(len(contents)), minio.PutObjectOptions{}); err != nil {
					return err
				}
				return nil
			},
			expected: 1,
		},
		{
			name: "successNothingToDelete",
			req: &plugin.DeleteObjectsRequest{
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
				KeyPrefix: "obj/path",
			},
			// notice this is still 1, non-recursive always returns 1 on success, even if nothing was *actually* deleted
			expected: 1,
		},
		{
			name: "successRecursiveOneObjNoSlash",
			req: &plugin.DeleteObjectsRequest{
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
				KeyPrefix: "obj/path",
				Recursive: true,
			},
			setup: func(cl *minio.Client, req *plugin.DeleteObjectsRequest) error {
				contents := "test file contents"
				file := bytes.NewBufferString(contents)
				if _, err := cl.PutObject(ctx, bucketName, req.KeyPrefix, file, int64(len(contents)), minio.PutObjectOptions{}); err != nil {
					return err
				}
				return nil
			},
			expected: 1,
		},
		{
			name: "successRecursiveNothingToDelete",
			req: &plugin.DeleteObjectsRequest{
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
				KeyPrefix: "obj/path",
				Recursive: true,
			},
			expected: 0,
		},
		{
			name: "successRecursiveOneObj",
			req: &plugin.DeleteObjectsRequest{
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
				KeyPrefix: "obj/path/",
				Recursive: true,
			},
			setup: func(cl *minio.Client, req *plugin.DeleteObjectsRequest) error {
				contents := "test file contents"
				file := bytes.NewBufferString(contents)
				if _, err := cl.PutObject(ctx, bucketName, req.KeyPrefix+"resr", file, int64(len(contents)), minio.PutObjectOptions{}); err != nil {
					return err
				}
				return nil
			},
			expected: 1,
		},
		{
			name: "successRecursiveManyObj",
			req: &plugin.DeleteObjectsRequest{
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
				KeyPrefix: "obj/path/",
				Recursive: true,
			},
			setup: func(cl *minio.Client, req *plugin.DeleteObjectsRequest) error {
				contents := "test file contents"
				for i := 0; i < 10; i++ {
					file := bytes.NewBufferString(contents)
					if _, err := cl.PutObject(ctx, bucketName, req.KeyPrefix+fmt.Sprint(i), file, int64(len(contents)), minio.PutObjectOptions{}); err != nil {
						return err
					}
				}
				return nil
			},
			expected: 10,
		},
	}

	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			cl, err := minio.New(server.ApiAddr, &minio.Options{
				Creds:  credentials.NewStaticV4(server.RootUsername, server.RootPassword, ""),
				Secure: false,
			})
			require.NoError(err)

			if tt.setup != nil {
				require.NoError(tt.setup(cl, tt.req))
			}

			sp := new(StoragePlugin)
			res, err := sp.DeleteObjects(ctx, tt.req)

			if tt.err != "" {
				assert.NotNil(status.Convert(err))
				assert.ErrorContains(err, tt.err)
				assert.Equal(tt.errCode.String(), status.Code(err).String())
				return
			}

			require.NotNil(res)
			assert.Equal(tt.expected, res.ObjectsDeleted)

			// make sure they were actually deleted on the server
			obj := 0
			for range cl.ListObjects(ctx, bucketName, minio.ListObjectsOptions{
				// we don't add the slash back here cause we want to make sure everything is gone
				Prefix:    path.Join(tt.req.Bucket.GetBucketPrefix(), tt.req.GetKeyPrefix()),
				Recursive: true,
			}) {
				obj++
			}
			assert.Equal(0, obj)
		})
	}
}

func TestDryRun(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name         string
		minioClFn    func(t *testing.T, s *internaltest.MinioServer) *minio.Client
		makeBucketFn func(t *testing.T, cl *minio.Client) string
		// This test verifies that each message in the err slice is contained in
		// the error string, effectively &&-ing the checks together.
		expErrMsgs     []string
		expPermissions *pb.Permissions
	}{
		{
			name:         "bucketNotExists",
			makeBucketFn: func(t *testing.T, cl *minio.Client) string { return "unknownbucket" },
			expErrMsgs:   []string{"The specified bucket does not exist"},
			expPermissions: &pb.Permissions{
				Write:  &pb.Permission{State: pb.StateType_STATE_TYPE_ERROR, ErrorDetails: "The specified bucket does not exist"},
				Read:   &pb.Permission{State: pb.StateType_STATE_TYPE_ERROR, ErrorDetails: "The specified bucket does not exist"},
				Delete: &pb.Permission{State: pb.StateType_STATE_TYPE_ERROR, ErrorDetails: "The specified bucket does not exist"},
			},
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
			expPermissions: &pb.Permissions{
				Write: &pb.Permission{State: pb.StateType_STATE_TYPE_ERROR, ErrorDetails: "Access Denied."},
				// The write permission is denied, so the any read operation will return with a no such key error.
				Read:   &pb.Permission{State: pb.StateType_STATE_TYPE_UNKNOWN, ErrorDetails: "The specified key does not exist."},
				Delete: &pb.Permission{State: pb.StateType_STATE_TYPE_OK},
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
			expPermissions: &pb.Permissions{
				Write:  &pb.Permission{State: pb.StateType_STATE_TYPE_OK},
				Read:   &pb.Permission{State: pb.StateType_STATE_TYPE_ERROR, ErrorDetails: "Access Denied."},
				Delete: &pb.Permission{State: pb.StateType_STATE_TYPE_OK},
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
			expPermissions: &pb.Permissions{
				Write:  &pb.Permission{State: pb.StateType_STATE_TYPE_OK},
				Read:   &pb.Permission{State: pb.StateType_STATE_TYPE_ERROR, ErrorDetails: "Access Denied."},
				Delete: &pb.Permission{State: pb.StateType_STATE_TYPE_OK},
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
			expPermissions: &pb.Permissions{
				Write:  &pb.Permission{State: pb.StateType_STATE_TYPE_OK},
				Read:   &pb.Permission{State: pb.StateType_STATE_TYPE_OK},
				Delete: &pb.Permission{State: pb.StateType_STATE_TYPE_ERROR, ErrorDetails: "Access Denied."},
			},
		},
		{
			name: "Invalid Access Key Id",
			minioClFn: func(t *testing.T, s *internaltest.MinioServer) *minio.Client {
				cl, err := minio.New(s.ApiAddr, &minio.Options{
					Creds:  credentials.NewStaticV4("invalidAccessKey", "invalidSecretKey", ""),
					Secure: false,
				})
				require.NoError(t, err)

				return cl
			},
			makeBucketFn: func(t *testing.T, cl *minio.Client) string {
				bucketName := "testdryrun-invalidaccesskeyid"
				_ = cl.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{})

				return bucketName
			},
			expErrMsgs: []string{
				"The Access Key Id you provided does not exist in our records",
			},
			expPermissions: &pb.Permissions{
				Write:  &pb.Permission{State: pb.StateType_STATE_TYPE_ERROR, ErrorDetails: "The Access Key Id you provided does not exist in our records."},
				Read:   &pb.Permission{State: pb.StateType_STATE_TYPE_ERROR, ErrorDetails: "The Access Key Id you provided does not exist in our records."},
				Delete: &pb.Permission{State: pb.StateType_STATE_TYPE_ERROR, ErrorDetails: "The Access Key Id you provided does not exist in our records."},
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
			expPermissions: &pb.Permissions{
				Write:  &pb.Permission{State: pb.StateType_STATE_TYPE_OK},
				Read:   &pb.Permission{State: pb.StateType_STATE_TYPE_OK},
				Delete: &pb.Permission{State: pb.StateType_STATE_TYPE_OK},
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
			per, err := dryRun(ctx, minioClient, &storagebuckets.StorageBucket{
				BucketName: bucketName,
			})
			if tt.expPermissions != nil {
				assert.Equal(t, tt.expPermissions.GetWrite().GetState(), per.GetWrite().GetState())
				assert.Equal(t, tt.expPermissions.GetRead().GetState(), per.GetRead().GetState())
				assert.Equal(t, tt.expPermissions.GetDelete().GetState(), per.GetDelete().GetState())

				assert.Contains(t, tt.expPermissions.GetWrite().GetErrorDetails(), per.GetWrite().GetErrorDetails())
				assert.Contains(t, tt.expPermissions.GetRead().GetErrorDetails(), per.GetRead().GetErrorDetails())
				assert.Contains(t, tt.expPermissions.GetDelete().GetErrorDetails(), per.GetDelete().GetErrorDetails())
			}
			require.NotNil(t, per)
			if len(tt.expErrMsgs) > 0 {
				for _, errMsg := range tt.expErrMsgs {
					require.ErrorContains(t, err.Unwrap(), errMsg)
				}
				return
			}

			require.NoError(t, err.Unwrap())
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

func TestErrorToStatus(t *testing.T) {
	t.Run("nilErr", func(t *testing.T) {
		st := errorToStatus(codes.Internal, "failed to do the thing", nil, nil)
		require.NotNil(t, st)
		require.Contains(t, st.String(), "failed to do the thing: no error from storage service provider")
		require.Equal(t, codes.Internal, st.Code())
	})

	t.Run("requestTimeout", func(t *testing.T) {
		st := errorToStatus(codes.Internal, "failed to do the thing", minio.ErrorResponse{Code: "RequestTimeout"}, nil)
		require.NotNil(t, st)
		require.Contains(t, st.String(), "failed to do the thing: timeout exceeded when communicating with storage service provider")
		require.Equal(t, codes.DeadlineExceeded, st.Code())
	})

	t.Run("slowDown", func(t *testing.T) {
		st := errorToStatus(codes.Internal, "failed to do the thing", minio.ErrorResponse{Code: "SlowDown"}, nil)
		require.NotNil(t, st)
		require.Contains(t, st.String(), "failed to do the thing: received a throttling response from storage service provider")
		require.Equal(t, codes.Unavailable, st.Code())
	})

	t.Run("badDigest", func(t *testing.T) {
		st := errorToStatus(codes.Internal, "failed to do the thing", minio.ErrorResponse{Code: "BadDigest"}, nil)
		require.NotNil(t, st)
		require.Contains(t, st.String(), "failed to do the thing: storage checksum mismatch")
		require.Equal(t, codes.Aborted, st.Code())
	})

	t.Run("noSuchBucket", func(t *testing.T) {
		st := errorToStatus(codes.Internal, "failed to do the thing", minio.ErrorResponse{Code: "NoSuchBucket"}, nil)
		require.NotNil(t, st)
		require.Contains(t, st.String(), "failed to do the thing: specified storage bucket does not exist")
		require.Equal(t, codes.NotFound, st.Code())
	})

	t.Run("noSuchKey", func(t *testing.T) {
		st := errorToStatus(codes.Internal, "failed to do the thing", minio.ErrorResponse{Code: "NoSuchKey"}, nil)
		require.NotNil(t, st)
		require.Contains(t, st.String(), "failed to do the thing: specified object does not exist")
		require.Equal(t, codes.NotFound, st.Code())
	})

	t.Run("statusCode400", func(t *testing.T) {
		st := errorToStatus(codes.Internal, "failed to do the thing", minio.ErrorResponse{StatusCode: 400, Message: "oops there was an error doing the thing"}, nil)
		require.NotNil(t, st)
		require.Contains(t, st.String(), "failed to do the thing: received a bad request response from storage service provider: oops there was an error doing the thing")
		require.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("permissionsErr", func(t *testing.T) {
		tests := []struct {
			name                 string
			code                 codes.Code
			errMsg               string
			err                  error
			reqType              any
			expStatusContains    string
			statusDetailsCheckFn func(t *testing.T, p *pb.Permissions)
		}{
			{
				name:              "headObject",
				code:              codes.Internal,
				errMsg:            "head object failed",
				err:               minio.ErrorResponse{StatusCode: 401, Code: "AccessDenied", Message: "object access denied"},
				reqType:           pb.HeadObjectRequest{},
				expStatusContains: "head object failed: object access denied",
				statusDetailsCheckFn: func(t *testing.T, in *pb.Permissions) {
					require.Empty(t, cmp.Diff(
						in.GetRead(),
						&pb.Permission{State: pb.StateType_STATE_TYPE_ERROR, ErrorDetails: "object access denied"},
						protocmp.Transform(),
						protocmp.IgnoreFields(in.GetRead(), "checked_at"),
					))
				},
			},
			{
				name:              "headObjectReqPtr",
				code:              codes.Internal,
				errMsg:            "head object failed",
				err:               minio.ErrorResponse{StatusCode: 401, Code: "AccessDenied", Message: "object access denied"},
				reqType:           &pb.HeadObjectRequest{},
				expStatusContains: "head object failed: object access denied",
				statusDetailsCheckFn: func(t *testing.T, in *pb.Permissions) {
					require.Empty(t, cmp.Diff(
						in.GetRead(),
						&pb.Permission{State: pb.StateType_STATE_TYPE_ERROR, ErrorDetails: "object access denied"},
						protocmp.Transform(),
						protocmp.IgnoreFields(in.GetRead(), "checked_at"),
					))
				},
			},
			{
				name:              "getObject",
				code:              codes.Internal,
				errMsg:            "get object failed",
				err:               minio.ErrorResponse{StatusCode: 401, Code: "AccessDenied", Message: "object access denied"},
				reqType:           pb.GetObjectRequest{},
				expStatusContains: "get object failed: object access denied",
				statusDetailsCheckFn: func(t *testing.T, in *pb.Permissions) {
					require.Empty(t, cmp.Diff(
						in.GetRead(),
						&pb.Permission{State: pb.StateType_STATE_TYPE_ERROR, ErrorDetails: "object access denied"},
						protocmp.Transform(),
						protocmp.IgnoreFields(in.GetRead(), "checked_at"),
					))
				},
			},
			{
				name:              "getObjectReqPtr",
				code:              codes.Internal,
				errMsg:            "get object failed",
				err:               minio.ErrorResponse{StatusCode: 401, Code: "AccessDenied", Message: "object access denied"},
				reqType:           &pb.GetObjectRequest{},
				expStatusContains: "get object failed: object access denied",
				statusDetailsCheckFn: func(t *testing.T, in *pb.Permissions) {
					require.Empty(t, cmp.Diff(
						in.GetRead(),
						&pb.Permission{State: pb.StateType_STATE_TYPE_ERROR, ErrorDetails: "object access denied"},
						protocmp.Transform(),
						protocmp.IgnoreFields(in.GetRead(), "checked_at"),
					))
				},
			},
			{
				name:              "putObject",
				code:              codes.Internal,
				errMsg:            "put object failed",
				err:               minio.ErrorResponse{StatusCode: 401, Code: "AccessDenied", Message: "object access denied"},
				reqType:           pb.PutObjectRequest{},
				expStatusContains: "put object failed: object access denied",
				statusDetailsCheckFn: func(t *testing.T, in *pb.Permissions) {
					require.Empty(t, cmp.Diff(
						in.GetWrite(),
						&pb.Permission{State: pb.StateType_STATE_TYPE_ERROR, ErrorDetails: "object access denied"},
						protocmp.Transform(),
						protocmp.IgnoreFields(in.GetRead(), "checked_at"),
					))
				},
			},
			{
				name:              "putObjectReqPtr",
				code:              codes.Internal,
				errMsg:            "put object failed",
				err:               minio.ErrorResponse{StatusCode: 401, Code: "AccessDenied", Message: "object access denied"},
				reqType:           &pb.PutObjectRequest{},
				expStatusContains: "put object failed: object access denied",
				statusDetailsCheckFn: func(t *testing.T, in *pb.Permissions) {
					require.Empty(t, cmp.Diff(
						in.GetWrite(),
						&pb.Permission{State: pb.StateType_STATE_TYPE_ERROR, ErrorDetails: "object access denied"},
						protocmp.Transform(),
						protocmp.IgnoreFields(in.GetRead(), "checked_at"),
					))
				},
			},
			{
				name:              "deleteObjects",
				code:              codes.Internal,
				errMsg:            "delete objects failed",
				err:               minio.ErrorResponse{StatusCode: 401, Code: "AccessDenied", Message: "object access denied"},
				reqType:           pb.DeleteObjectsRequest{},
				expStatusContains: "delete objects failed: object access denied",
				statusDetailsCheckFn: func(t *testing.T, in *pb.Permissions) {
					require.Empty(t, cmp.Diff(
						in.GetDelete(),
						&pb.Permission{State: pb.StateType_STATE_TYPE_ERROR, ErrorDetails: "object access denied"},
						protocmp.Transform(),
						protocmp.IgnoreFields(in.GetRead(), "checked_at"),
					))
				},
			},
			{
				name:              "deleteObjectsReqPtr",
				code:              codes.Internal,
				errMsg:            "delete objects failed",
				err:               minio.ErrorResponse{StatusCode: 401, Code: "AccessDenied", Message: "object access denied"},
				reqType:           &pb.DeleteObjectsRequest{},
				expStatusContains: "delete objects failed: object access denied",
				statusDetailsCheckFn: func(t *testing.T, in *pb.Permissions) {
					require.Empty(t, cmp.Diff(
						in.GetDelete(),
						&pb.Permission{State: pb.StateType_STATE_TYPE_ERROR, ErrorDetails: "object access denied"},
						protocmp.Transform(),
						protocmp.IgnoreFields(in.GetRead(), "checked_at"),
					))
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				st := errorToStatus(tt.code, tt.errMsg, tt.err, tt.reqType)
				require.NotNil(t, st)

				require.Contains(t, st.String(), tt.expStatusContains)
				require.Equal(t, codes.Internal, tt.code)

				require.Len(t, st.Details(), 1)
				require.IsType(t, st.Details()[0], &pb.StorageBucketCredentialState{})

				state := st.Details()[0].(*pb.StorageBucketCredentialState)
				require.NotNil(t, state.GetState())
				if tt.statusDetailsCheckFn != nil {
					tt.statusDetailsCheckFn(t, state.GetState())
				}
			})
		}
	})

	t.Run("unknownErr", func(t *testing.T) {
		st := errorToStatus(codes.Internal, "failed to do the thing", fmt.Errorf("oops the thing failed but it's just a normal go error"), nil)
		require.NotNil(t, st)
		require.Contains(t, st.String(), "failed to do the thing: oops the thing failed but it's just a normal go error")
		require.Equal(t, codes.Internal, st.Code())
		require.Len(t, st.Details(), 1)
		require.Empty(t, cmp.Diff(
			&pb.StorageBucketCredentialState{State: &pb.Permissions{}},
			st.Details()[0],
			protocmp.Transform(),
		))
	})
}
