// Copyright IBM Corp. 2024, 2025
// SPDX-License-Identifier: MPL-2.0

package client_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary-plugin-minio/internal/client"
	internaltest "github.com/hashicorp/boundary-plugin-minio/internal/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServiceAccount(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	assert, require := assert.New(t), require.New(t)

	server := internaltest.NewMinioServer(t)
	c, err := client.New(server.ApiAddr, server.RootUsername, server.RootPassword)
	require.NoError(err)
	assert.NotNil(c)

	creds, err := c.AddServiceAccount(ctx, client.AddServiceAccountReq{})
	require.NoError(err)

	// We just added service account it should be valid
	err = c.EnsureServiceAccount(ctx, creds.AccessKeyId)
	require.NoError(err)

	err = c.DeleteServiceAccount(ctx, creds.AccessKeyId)
	require.NoError(err)

	// Now that we have deleted the service account it should be invalid
	err = c.EnsureServiceAccount(ctx, creds.AccessKeyId)
	require.Error(err)
}
