// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package storage

import (
	"context"
	"fmt"

	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
)

var _ pb.StoragePluginServiceServer = (*StoragePlugin)(nil)

// StoragePlugin implements the StoragePluginServiceServer interface for the
// MinIO storage service plugin.
type StoragePlugin struct {
	pb.UnimplementedStoragePluginServiceServer
}

// OnCreateStorageBucket is a hook that runs when a storage bucket is created.
func (sp *StoragePlugin) OnCreateStorageBucket(ctx context.Context, req *pb.OnCreateStorageBucketRequest) (*pb.OnCreateStorageBucketResponse, error) {
	return nil, fmt.Errorf("unimplemented")
}

// OnUpdateStorageBucket is a hook that runs when a storage bucket is updated.
func (sp *StoragePlugin) OnUpdateStorageBucket(ctx context.Context, req *pb.OnUpdateStorageBucketRequest) (*pb.OnUpdateStorageBucketResponse, error) {
	return nil, fmt.Errorf("unimplemented")
}

// OnDeleteStorageBucket is a hook that runs when a storage bucket is deleted.
func (sp *StoragePlugin) OnDeleteStorageBucket(ctx context.Context, req *pb.OnDeleteStorageBucketRequest) (*pb.OnDeleteStorageBucketResponse, error) {
	return nil, fmt.Errorf("unimplemented")
}

// ValidatePermissions is a hook that checks if the secrets associated with the
// storage bucket meet the requirements of the plugin.
func (sp *StoragePlugin) ValidatePermissions(ctx context.Context, req *pb.ValidatePermissionsRequest) (*pb.ValidatePermissionsResponse, error) {
	return nil, fmt.Errorf("unimplemented")
}

// HeadObject is a hook that retrieves metadata about an object.
func (sp *StoragePlugin) HeadObject(ctx context.Context, req *pb.HeadObjectRequest) (*pb.HeadObjectResponse, error) {
	return nil, fmt.Errorf("unimplemented")
}

// GetObject is a hook that retrieves objects.
func (sp *StoragePlugin) GetObject(req *pb.GetObjectRequest, objServer pb.StoragePluginService_GetObjectServer) error {
	return fmt.Errorf("unimplemented")
}

// PutObject is a hook that reads a file stored on local disk and stores it to
// an external object store.
func (sp *StoragePlugin) PutObject(ctx context.Context, req *pb.PutObjectRequest) (*pb.PutObjectResponse, error) {
	return nil, fmt.Errorf("unimplemented")
}

// DeleteObjects deletes one or many files in an external object store via a
// provided key prefix.
func (sp *StoragePlugin) DeleteObjects(ctx context.Context, req *pb.DeleteObjectsRequest) (*pb.DeleteObjectsResponse, error) {
	return nil, fmt.Errorf("unimplemented")
}
