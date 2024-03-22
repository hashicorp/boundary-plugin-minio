package storage

import (
	"context"
	"encoding/json"
	"testing"

	internaltest "github.com/hashicorp/boundary-plugin-minio/internal/testing"
	"github.com/minio/madmin-go/v3"
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
		ss         *StorageSecrets
		expErrMsg  string
		credDelErr bool
	}{
		{
			name: "notUsingServiceAccount",
			ss: &StorageSecrets{
				AccessKeyId:     server.RootUsername,
				SecretAccessKey: server.RootPassword,
			},
			expErrMsg: "failed to ensure minio service account credentials: failed to obtain service account info: The specified service account is not found",
		},
		{
			name: "addServiceAccountFail",
			ss: func() *StorageSecrets {
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

				return &StorageSecrets{
					AccessKeyId:     creds.AccessKey,
					SecretAccessKey: creds.SecretKey,
				}
			}(),
			expErrMsg: "failed to create new minio service account: Access Denied",
		},
		{
			name: "credentialDeletionFail",
			ss: func() *StorageSecrets {
				creds, err := server.AdminClient.AddServiceAccount(ctx, madmin.AddServiceAccountReq{})
				require.NoError(t, err)

				return &StorageSecrets{
					AccessKeyId:     creds.AccessKey,
					SecretAccessKey: creds.SecretKey,
				}
			}(),
			credDelErr: true,
		},
		{
			name: "success",
			ss: func() *StorageSecrets {
				creds, err := server.AdminClient.AddServiceAccount(ctx, madmin.AddServiceAccountReq{})
				require.NoError(t, err)

				return &StorageSecrets{
					AccessKeyId:     creds.AccessKey,
					SecretAccessKey: creds.SecretKey,
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

			ss, delFn, err := rotateCredentials(context.Background(), bucketName, sa, tt.ss)
			if tt.expErrMsg != "" {
				require.ErrorContains(t, err, tt.expErrMsg)
				require.Nil(t, ss)
				require.Nil(t, delFn)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, ss)
			require.NotNil(t, delFn)
			require.NotEqual(t, ss.AccessKeyId, tt.ss.AccessKeyId)
			require.NotEqual(t, ss.SecretAccessKey, tt.ss.SecretAccessKey)
			require.NotEmpty(t, ss.LastRotatedTime)

			// Ensure old creds still exist since the callback hasn't been
			// called. We then make the delete call and finally assert that the
			// credential was removed if there was no error when attempting to
			// delete.
			_, err = server.AdminClient.InfoServiceAccount(ctx, tt.ss.AccessKeyId)
			require.NoError(t, err)

			if tt.credDelErr {
				sa.EndpointUrl = "localhost:1"
				require.ErrorContains(t, delFn(), "failed to delete minio service account")
				require.ErrorContains(t, delFn(), "failed to delete minio service account") // 2nd call should return the same state (due to sync.Once).

				_, err := server.AdminClient.InfoServiceAccount(ctx, tt.ss.AccessKeyId)
				require.NoError(t, err)
				return
			} else {
				require.NoError(t, delFn())
				require.NoError(t, delFn()) // 2nd call should return the same state (due to sync.Once).
			}

			_, err = server.AdminClient.InfoServiceAccount(ctx, tt.ss.AccessKeyId)
			require.ErrorContains(t, err, "service account is not found")
		})
	}
}
