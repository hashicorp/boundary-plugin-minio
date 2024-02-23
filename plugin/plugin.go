// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package plugin

import (
	"github.com/hashicorp/boundary-plugin-minio/plugin/service/storage"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
)

var (
	_ pb.StoragePluginServiceServer = (*storage.StoragePlugin)(nil)
)

// MinioPlugin contains a collection of all MinIO plugin services.
type MinioPlugin struct {
	// StoragePlugin implements the StoragePluginServiceServer interface for
	// supporting storing and retrieving BSR data from a MinIO instance.
	*storage.StoragePlugin
}

// NewMinioPlugin creates a new instance of the MinIO Plugin.
func NewMinioPlugin() *MinioPlugin {
	return &MinioPlugin{
		StoragePlugin: &storage.StoragePlugin{},
	}
}
