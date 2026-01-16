// Copyright IBM Corp. 2024, 2025
// SPDX-License-Identifier: MPL-2.0

package storage

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hashicorp/boundary-plugin-minio/internal/client"
	internaltest "github.com/hashicorp/boundary-plugin-minio/internal/testing"
	"github.com/minio/minio-go/v7"
	"github.com/stretchr/testify/require"
)

func TestRotateCredentials(t *testing.T) {
	ctx := context.Background()
	server := internaltest.NewMinioServer(t)

	bucketName := "test-bucket"
	err := server.Client.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{})
	require.NoError(t, err)

	tests := []struct {
		name       string
		inSec      *StorageSecrets
		expErrMsg  string
		credDelErr bool
	}{
		{
			name: "notUsingServiceAccount",
			inSec: &StorageSecrets{
				AccessKeyId:     server.RootUsername,
				SecretAccessKey: server.RootPassword,
			},
			expErrMsg: "failed to ensure minio service account credentials: failed to obtain service account info: The specified service account is not found",
		},
		{
			name: "addServiceAccountFail",
			inSec: func() *StorageSecrets {
				creds, err := server.AdminClient.AddServiceAccount(ctx, client.AddServiceAccountReq{
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

				return &StorageSecrets{
					AccessKeyId:     creds.AccessKeyId,
					SecretAccessKey: creds.SecretAccessKey,
				}
			}(),
			expErrMsg: "failed to create new minio service account: Access Denied",
		},
		{
			name: "credentialDeletionFail",
			inSec: func() *StorageSecrets {
				creds, err := server.AdminClient.AddServiceAccount(ctx, client.AddServiceAccountReq{})
				require.NoError(t, err)

				return &StorageSecrets{
					AccessKeyId:     creds.AccessKeyId,
					SecretAccessKey: creds.SecretAccessKey,
				}
			}(),
			credDelErr: true,
		},
		{
			name: "success",
			inSec: func() *StorageSecrets {
				creds, err := server.AdminClient.AddServiceAccount(ctx, client.AddServiceAccountReq{})
				require.NoError(t, err)

				return &StorageSecrets{
					AccessKeyId:     creds.AccessKeyId,
					SecretAccessKey: creds.SecretAccessKey,
				}
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sa := &StorageAttributes{
				EndpointUrl: server.ApiAddr,
				UseSSL:      false,
			}

			outSec, delFn, err := rotateCredentials(context.Background(), bucketName, sa, tt.inSec)
			if tt.expErrMsg != "" {
				require.ErrorContains(t, err, tt.expErrMsg)
				require.Nil(t, outSec)
				require.Nil(t, delFn)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, outSec)
			require.NotNil(t, delFn)
			require.NotEqual(t, outSec.AccessKeyId, tt.inSec.AccessKeyId)
			require.NotEqual(t, outSec.SecretAccessKey, tt.inSec.SecretAccessKey)
			require.NotEmpty(t, outSec.LastRotatedTime)

			// Ensure old creds still exist since the callback hasn't been
			// called. We then make the delete call and finally assert that the
			// credential was removed if there was no error when attempting to
			// delete.
			err = server.AdminClient.EnsureServiceAccount(ctx, tt.inSec.AccessKeyId)
			require.NoError(t, err)

			if tt.credDelErr {
				sa.EndpointUrl = "localhost:1"
				require.ErrorContains(t, delFn(), "failed to delete minio service account")
				require.ErrorContains(t, delFn(), "failed to delete minio service account") // 2nd call should return the same state (due to sync.Once).

				err := server.AdminClient.EnsureServiceAccount(ctx, tt.inSec.AccessKeyId)
				require.NoError(t, err)
				return
			} else {
				require.NoError(t, delFn())
				require.NoError(t, delFn()) // 2nd call should return the same state (due to sync.Once).
			}

			err = server.AdminClient.EnsureServiceAccount(ctx, tt.inSec.AccessKeyId)
			require.ErrorContains(t, err, "service account is not found")
		})
	}
}
