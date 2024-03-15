// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path"

	"github.com/google/uuid"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/storagebuckets"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	madmin "github.com/minio/madmin-go/v3"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var _ pb.StoragePluginServiceServer = (*StoragePlugin)(nil)

// StoragePlugin implements the StoragePluginServiceServer interface for the
// MinIO storage service plugin.
type StoragePlugin struct {
	pb.UnimplementedStoragePluginServiceServer
}

// OnCreateStorageBucket is a hook that runs when a storage bucket is created.
func (sp *StoragePlugin) OnCreateStorageBucket(ctx context.Context, req *pb.OnCreateStorageBucketRequest) (*pb.OnCreateStorageBucketResponse, error) {
	bucket := req.GetBucket()
	if bucket == nil {
		return nil, status.Error(codes.InvalidArgument, "no storage bucket information found")
	}
	if bucket.GetBucketName() == "" {
		return nil, status.Error(codes.InvalidArgument, "storage bucket name is required")
	}

	sa, err := getStorageAttributes(bucket.GetAttributes())
	if err != nil {
		return nil, err
	}

	sec, err := getStorageSecrets(bucket.GetSecrets())
	if err != nil {
		return nil, err
	}

	err = ensureServiceAccount(ctx, sa, sec)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to ensure service account: %v", err)
	}

	cl, err := minio.New(sa.EndpointUrl, &minio.Options{
		Creds:  credentials.NewStaticV4(sec.AccessKeyId, sec.SecretAccessKey, ""),
		Secure: sa.UseSSL,
		Region: sa.Region,
	})
	if err != nil {
		return nil, status.Errorf(codes.Unknown, "failed to create minio sdk client: %v", err)
	}

	err = dryRun(ctx, cl, bucket)
	if err != nil {
		return nil, status.Errorf(codes.Unknown, "failed to verify provided minio environment: %v", err)
	}

	persistedData, err := structpb.NewStruct(sec.AsMap())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to convert storage attributes to protobuf struct: %v", err)
	}
	return &pb.OnCreateStorageBucketResponse{
		Persisted: &storagebuckets.StorageBucketPersisted{Data: persistedData},
	}, nil
}

// OnUpdateStorageBucket is a hook that runs when a storage bucket is updated.
func (sp *StoragePlugin) OnUpdateStorageBucket(ctx context.Context, req *pb.OnUpdateStorageBucketRequest) (*pb.OnUpdateStorageBucketResponse, error) {
	newBucket := req.GetNewBucket()
	if newBucket == nil {
		return nil, status.Error(codes.InvalidArgument, "new bucket is required")
	}
	if newBucket.BucketName == "" {
		return nil, status.Error(codes.InvalidArgument, "new bucketName is required")
	}
	oldBucket := req.GetCurrentBucket()
	if oldBucket == nil {
		return nil, status.Error(codes.InvalidArgument, "current bucket is required")
	}

	// current attributes
	osa, err := getStorageAttributes(oldBucket.GetAttributes())
	if err != nil {
		return nil, err
	}

	// new attributes and secrets
	nsa, err := getStorageAttributes(newBucket.GetAttributes())
	if err != nil {
		return nil, err
	}

	sec, err := getStorageSecrets(newBucket.GetSecrets())
	if err != nil {
		return nil, err
	}

	switch {
	case newBucket.GetBucketName() != oldBucket.GetBucketName():
		return nil, status.Errorf(codes.InvalidArgument, "cannot update attribute BucketName")
	case newBucket.GetBucketPrefix() != oldBucket.GetBucketPrefix():
		return nil, status.Errorf(codes.InvalidArgument, "cannot update attribute BucketPrefix")
	case nsa.Region != osa.Region:
		return nil, status.Errorf(codes.InvalidArgument, "cannot update attribute Region")
	case nsa.EndpointUrl != osa.EndpointUrl:
		return nil, status.Errorf(codes.InvalidArgument, "cannot update attribute EndpointUrl")
	}

	if err = ensureServiceAccount(ctx, nsa, sec); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to ensure service account: %s", err)
	}

	cl, err := minio.New(nsa.EndpointUrl, &minio.Options{
		Creds:  credentials.NewStaticV4(sec.AccessKeyId, sec.SecretAccessKey, ""),
		Secure: nsa.UseSSL,
		Region: nsa.Region,
	})
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to create minio sdk client: %s", err)
	}

	if err = dryRun(ctx, cl, newBucket); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to verify provided minio environment: %s", err)
	}

	persisted, err := structpb.NewStruct(sec.AsMap())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to convert storage attributes to protobuf struct: %s", err)
	}

	return &pb.OnUpdateStorageBucketResponse{
		Persisted: &storagebuckets.StorageBucketPersisted{Data: persisted},
	}, nil
}

// OnDeleteStorageBucket is a hook that runs when a storage bucket is deleted.
// Since this plugin manages no state at the moment, this function is a no-op.
func (sp *StoragePlugin) OnDeleteStorageBucket(ctx context.Context, req *pb.OnDeleteStorageBucketRequest) (*pb.OnDeleteStorageBucketResponse, error) {
	return &pb.OnDeleteStorageBucketResponse{}, nil
}

// ValidatePermissions is a hook that checks if the secrets associated with the
// storage bucket meet the requirements of the plugin.
func (sp *StoragePlugin) ValidatePermissions(ctx context.Context, req *pb.ValidatePermissionsRequest) (*pb.ValidatePermissionsResponse, error) {
	bucket := req.GetBucket()
	if bucket == nil {
		return nil, status.Error(codes.InvalidArgument, "no storage bucket information found")
	}
	if bucket.GetBucketName() == "" {
		return nil, status.Error(codes.InvalidArgument, "storage bucket name is required")
	}

	sa, err := getStorageAttributes(bucket.GetAttributes())
	if err != nil {
		return nil, err
	}

	sec, err := getStorageSecrets(bucket.GetSecrets())
	if err != nil {
		return nil, err
	}

	err = ensureServiceAccount(ctx, sa, sec)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to ensure service account: %v", err)
	}

	cl, err := minio.New(sa.EndpointUrl, &minio.Options{
		Creds:  credentials.NewStaticV4(sec.AccessKeyId, sec.SecretAccessKey, ""),
		Secure: sa.UseSSL,
		Region: sa.Region,
	})
	if err != nil {
		return nil, status.Errorf(codes.Unknown, "failed to create minio sdk client: %v", err)
	}

	err = dryRun(ctx, cl, bucket)
	if err != nil {
		return nil, status.Errorf(codes.Unknown, "failed to verify provided minio environment: %v", err)
	}

	return &pb.ValidatePermissionsResponse{}, nil
}

// HeadObject is a hook that retrieves metadata about an object.
func (sp *StoragePlugin) HeadObject(ctx context.Context, req *pb.HeadObjectRequest) (*pb.HeadObjectResponse, error) {
	bucket := req.GetBucket()
	if bucket == nil {
		return nil, status.Error(codes.InvalidArgument, "no storage bucket information found")
	}
	if bucket.GetBucketName() == "" {
		return nil, status.Error(codes.InvalidArgument, "storage bucket name is required")
	}

	if req.GetKey() == "" {
		return nil, status.Error(codes.InvalidArgument, "object key is required")
	}

	sa, err := getStorageAttributes(bucket.GetAttributes())
	if err != nil {
		return nil, err
	}

	sec, err := getStorageSecrets(bucket.GetSecrets())
	if err != nil {
		return nil, err
	}

	cl, err := minio.New(sa.EndpointUrl, &minio.Options{
		Creds:  credentials.NewStaticV4(sec.AccessKeyId, sec.SecretAccessKey, ""),
		Secure: sa.UseSSL,
		Region: sa.Region,
	})
	if err != nil {
		return nil, status.Errorf(codes.Unknown, "failed to create minio sdk client: %v", err)
	}

	objKey := path.Join(bucket.GetBucketPrefix(), req.GetKey())
	oi, err := cl.StatObject(ctx, bucket.GetBucketName(), objKey, minio.StatObjectOptions{})
	if err != nil {
		return nil, status.Errorf(codes.Unknown, "failed to stat object: %v", err)
	}

	return &pb.HeadObjectResponse{
		ContentLength: oi.Size,
		LastModified:  timestamppb.New(oi.LastModified),
	}, nil
}

// GetObject is a hook that retrieves objects.
func (sp *StoragePlugin) GetObject(req *pb.GetObjectRequest, objServer pb.StoragePluginService_GetObjectServer) error {
	return fmt.Errorf("unimplemented")
}

// PutObject is a hook that reads a file stored on local disk and stores it to
// an external object store.
func (sp *StoragePlugin) PutObject(ctx context.Context, req *pb.PutObjectRequest) (*pb.PutObjectResponse, error) {
	bucket := req.GetBucket()
	if bucket == nil {
		return nil, status.Error(codes.InvalidArgument, "no storage bucket information found")
	}
	if bucket.GetBucketName() == "" {
		return nil, status.Error(codes.InvalidArgument, "storage bucket name is required")
	}
	if req.GetKey() == "" {
		return nil, status.Error(codes.InvalidArgument, "object key is required")
	}
	if req.GetPath() == "" {
		return nil, status.Error(codes.InvalidArgument, "path is required")
	}

	sa, err := getStorageAttributes(bucket.GetAttributes())
	if err != nil {
		return nil, err
	}

	sec, err := getStorageSecrets(bucket.GetSecrets())
	if err != nil {
		return nil, err
	}

	file, err := os.Open(req.GetPath())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to open file: %v", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to read file info: %v", err)
	}
	if info.IsDir() {
		return nil, status.Error(codes.InvalidArgument, "path is not a file")
	}
	if info.Size() == 0 {
		return nil, status.Error(codes.InvalidArgument, "file is empty")
	}

	cl, err := minio.New(sa.EndpointUrl, &minio.Options{
		Creds:  credentials.NewStaticV4(sec.AccessKeyId, sec.SecretAccessKey, ""),
		Secure: sa.UseSSL,
		Region: sa.Region,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create minio sdk client: %v", err)
	}

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to calculate hash: %v", err)
	}
	checksum := base64.StdEncoding.EncodeToString(hash.Sum(nil))

	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to rewind file pointer: %v", err)
	}

	key := path.Join(bucket.GetBucketPrefix(), req.GetKey())
	res, err := cl.PutObject(ctx, bucket.GetBucketName(), key, file, info.Size(), minio.PutObjectOptions{
		UserMetadata: map[string]string{
			"x-amz-checksum-algorithm": "SHA256",
			"x-amz-checksum-sha256":    checksum,
		},
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to put object into minio: %v", err)
	}

	if res.ChecksumSHA256 == "" {
		return nil, status.Error(codes.Internal, "missing checksum response from minio")
	}
	if checksum != res.ChecksumSHA256 {
		return nil, status.Error(codes.Internal, "mismatched checksum")
	}
	decodedChecksum, err := base64.StdEncoding.DecodeString(res.ChecksumSHA256)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to decode checksum value from minio: %v", err)
	}
	return &pb.PutObjectResponse{
		ChecksumSha_256: decodedChecksum,
	}, nil
}

// DeleteObjects deletes one or many files in an external object store via a
// provided key prefix.
func (sp *StoragePlugin) DeleteObjects(ctx context.Context, req *pb.DeleteObjectsRequest) (*pb.DeleteObjectsResponse, error) {
	return nil, fmt.Errorf("unimplemented")
}

func dryRun(ctx context.Context, cl *minio.Client, bucket *storagebuckets.StorageBucket) error {
	objectKey := path.Join(bucket.GetBucketPrefix(), uuid.New().String())
	rd := bytes.NewReader([]byte("hashicorp boundary minio plugin access test"))
	_, err := cl.PutObject(ctx, bucket.GetBucketName(), objectKey, rd, rd.Size(), minio.PutObjectOptions{})
	if err != nil {
		return fmt.Errorf("failed to put object at %q: %w", objectKey, err)
	}

	_, err = cl.StatObject(ctx, bucket.GetBucketName(), objectKey, minio.StatObjectOptions{})
	if err != nil {
		return fmt.Errorf("failed to stat object at %q: %w", objectKey, err)
	}

	_, err = cl.GetObject(ctx, bucket.GetBucketName(), objectKey, minio.GetObjectOptions{})
	if err != nil {
		return fmt.Errorf("failed to get object at %q: %w", objectKey, err)
	}

	oiCh := cl.ListObjects(ctx, bucket.GetBucketName(), minio.ListObjectsOptions{Recursive: true})
	for oi := range oiCh {
		if oi.Err != nil {
			return fmt.Errorf("failed to list objects in bucket %q: %w", bucket.GetBucketName(), oi.Err)
		}
	}

	err = cl.RemoveObject(ctx, bucket.GetBucketName(), objectKey, minio.RemoveObjectOptions{})
	if err != nil {
		return fmt.Errorf("failed to remove object at %q: %w", objectKey, err)
	}

	return nil
}

func newMadminClient(sa *StorageAttributes, sec *StorageSecrets) (*madmin.AdminClient, error) {
	return madmin.NewWithOptions(sa.EndpointUrl, &madmin.Options{
		Creds:  credentials.NewStaticV4(sec.AccessKeyId, sec.SecretAccessKey, ""),
		Secure: sa.UseSSL,
	})
}

// ensureServiceAccount ensures the credentials we received belong to a MinIO
// service account. This plugin does not support using user credentials for its
// configuration.
func ensureServiceAccount(ctx context.Context, sa *StorageAttributes, sec *StorageSecrets) error {
	cl, err := newMadminClient(sa, sec)
	if err != nil {
		return fmt.Errorf("failed to create madmin client: %w", err)
	}

	if _, err = cl.InfoServiceAccount(ctx, sec.AccessKeyId); err != nil {
		return fmt.Errorf("failed to obtain service account info: %w", err)
	}

	return nil
}
