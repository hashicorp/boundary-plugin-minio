// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/minio/madmin-go/v3"
)

const (
	defaultPolicyTemplate = `{
		"Statement": [
			{
				"Action": [
					"s3:GetObject",
					"s3:GetObjectAttributes",
					"s3:PutObject",
					"s3:DeleteObject"
				],
				"Effect": "Allow",
				"Resource": "arn:aws:s3:::%[1]s/*"
			},
			{
				"Action": "s3:ListBucket",
				"Effect": "Allow",
				"Resource": "arn:aws:s3:::%[1]s"
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
	}`
)

type deleteInputCredsFn func() error

// rotateCredentials uses the incoming service account credentials to generate a
// new service account. It returns a new StorageSecrets object with the new
// service account credentials and a callback function to delete the service
// account provided in the input.
func rotateCredentials(ctx context.Context, bucketName string, sa *StorageAttributes, inSec *StorageSecrets) (*StorageSecrets, deleteInputCredsFn, error) {
	err := ensureServiceAccount(ctx, sa, inSec)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to ensure minio service account credentials: %w", err)
	}

	ac, err := newMadminClient(sa, inSec)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create minio admin client: %w", err)
	}

	policy := json.RawMessage(fmt.Sprintf(defaultPolicyTemplate, bucketName))
	newCreds, err := ac.AddServiceAccount(ctx, madmin.AddServiceAccountReq{
		Name:        "Boundary MinIO Service Account",
		Description: fmt.Sprintf("Boundary-managed MinIO service account for storage bucket '%s'", bucketName),
		Policy:      policy,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create new minio service account: %w", err)
	}

	newSec := &StorageSecrets{
		AccessKeyId:     newCreds.AccessKey,
		SecretAccessKey: newCreds.SecretKey,
		LastRotatedTime: time.Now(),
	}

	inCl := inSec.Clone()
	return newSec, sync.OnceValue(func() error {
		ac, err := newMadminClient(sa, inCl)
		if err != nil {
			return fmt.Errorf("failed to create minio admin client: %w", err)
		}
		err = ac.DeleteServiceAccount(ctx, inCl.AccessKeyId)
		if err != nil {
			return fmt.Errorf("failed to delete minio service account: %w", err)
		}
		return nil
	}), nil
}
