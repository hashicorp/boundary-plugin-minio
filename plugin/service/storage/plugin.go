// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package storage

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/hashicorp/boundary-plugin-minio/internal/client"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/storagebuckets"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var _ pb.StoragePluginServiceServer = (*StoragePlugin)(nil)

const (
	defaultGetObjectChunkSize = uint32(65536)
)

// StoragePlugin implements the StoragePluginServiceServer interface for the
// MinIO storage service plugin.
type StoragePlugin struct {
	pb.UnimplementedStoragePluginServiceServer
}

// NormalizeStorageBucketData is called by boundary before calling OnCreate or OnUpdate
//
// minio supports 3 attributes:
//   - endpoint_url
//   - region
//   - disable_credential_rotation
//
// of these, only endpoint is required and normalized. region and disable_credential_rotation
// are passed as-is, if they were provided
func (sp *StoragePlugin) NormalizeStorageBucketData(ctx context.Context, req *pb.NormalizeStorageBucketDataRequest) (*pb.NormalizeStorageBucketDataResponse, error) {
	sa, err := getStorageAttributes(req.GetAttributes())
	if err != nil {
		return nil, err
	}

	// re-add the scheme since getStorageAttributes removes it
	if sa.UseSSL {
		sa.EndpointUrl = "https://" + sa.EndpointUrl
	} else {
		sa.EndpointUrl = "http://" + sa.EndpointUrl
	}

	if sa.EndpointUrl, err = parseutil.NormalizeAddr(sa.EndpointUrl); err != nil {
		return nil, status.New(codes.InvalidArgument, fmt.Sprintf("failed to normalize provided %s: %s", ConstEndpointUrl, err.Error())).Err()
	}

	fields := map[string]*structpb.Value{
		ConstEndpointUrl: structpb.NewStringValue(sa.EndpointUrl),
	}

	// only EndpointUrl is required, so we need to check the rest
	if _, ok := req.GetAttributes().GetFields()[ConstRegion]; ok {
		fields[ConstRegion] = structpb.NewStringValue(sa.Region)
	}
	if _, ok := req.GetAttributes().GetFields()[ConstDisableCredentialRotation]; ok {
		fields[ConstDisableCredentialRotation] = structpb.NewBoolValue(sa.DisableCredentialRotation)
	}

	return &pb.NormalizeStorageBucketDataResponse{
		Attributes: &structpb.Struct{
			Fields: fields,
		},
	}, nil
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

	deleteOldCredsFn := func() error { return nil }
	if !sa.DisableCredentialRotation {
		newSec, fn, err := rotateCredentials(ctx, bucket.GetBucketName(), sa, sec)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "failed to rotate minio credentials: %v", err)
		}
		sec = newSec
		deleteOldCredsFn = fn
	}

	cl, err := minio.New(sa.EndpointUrl, &minio.Options{
		Creds:  credentials.NewStaticV4(sec.AccessKeyId, sec.SecretAccessKey, ""),
		Secure: sa.UseSSL,
		Region: sa.Region,
	})
	if err != nil {
		return nil, status.Errorf(codes.Unknown, "failed to create minio sdk client: %v", err)
	}

	p, dryRunErr := dryRun(ctx, cl, bucket)
	if dryRunErr.Len() > 0 {
		st := status.New(codes.InvalidArgument, fmt.Sprintf("failed to verify provided minio environment: %v", dryRunErr.Unwrap()))

		st, err = st.WithDetails(&pb.StorageBucketCredentialState{State: p})
		if err != nil {
			st = status.New(codes.Unknown, fmt.Sprintf("failed to verify provided minio environment: %v", dryRunErr.Unwrap()))
		}
		return nil, st.Err()
	}

	persistedData, err := structpb.NewStruct(sec.AsMap())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to convert storage attributes to protobuf struct: %v", err)
	}

	// Given that at this point everything is OK with the bucket, we shouldn't
	// let a failure to delete the old credentials fail the entire process. If
	// we ever establish a way to log non-critical errors in the plugin, log
	// this.
	_ = deleteOldCredsFn()

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
	osa, err := getStorageAttributes(oldBucket.GetAttributes())
	if err != nil {
		return nil, err
	}

	nsa, err := getStorageAttributes(newBucket.GetAttributes())
	if err != nil {
		return nil, err
	}

	sec, err := getStorageSecrets(req.GetPersisted().GetData())
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

	if nsa.DisableCredentialRotation && newBucket.GetSecrets() == nil {
		if !sec.LastRotatedTime.IsZero() {
			return nil, status.Error(codes.InvalidArgument, "cannot disable rotation for already-rotated credentials")
		}
	}

	deleteRotatedCredsFn := func() error { return nil }
	deleteOldPersistedCredsFn := func() error { return nil }
	if newBucket.GetSecrets() != nil {
		// Preemptively check if we're managing the current persisted
		// credentials and schedule them for later deletion if we are, since in
		// both rotation and non-rotation cases below, we'll be replacing these.
		if !sec.LastRotatedTime.IsZero() {
			sc := sec.Clone()
			deleteOldPersistedCredsFn = sync.OnceValue(func() error {
				ac, err := client.New(nsa.EndpointUrl, sec.AccessKeyId, sec.SecretAccessKey, client.WithUseSsl(nsa.UseSSL))
				if err != nil {
					return status.Errorf(codes.InvalidArgument, "failed to create client: %v", err)
				}
				err = ac.DeleteServiceAccount(ctx, sc.AccessKeyId)
				if err != nil {
					return fmt.Errorf("failed to delete minio service account: %w", err)
				}

				return nil
			})
		}

		newSec, err := getStorageSecrets(newBucket.GetSecrets())
		if err != nil {
			return nil, err
		}

		if !nsa.DisableCredentialRotation {
			// We have new incoming credentials and we're also rotating,
			// therefore we use incoming credentials to create a new service
			// account, then delete the incoming credentials. The existing
			// persisted credentials have already been scheduled for deletion
			// above (if applicable), so we don't need to do it here.
			rotatedSec, fn, err := rotateCredentials(ctx, newBucket.GetBucketName(), nsa, newSec)
			if err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "failed to rotate minio credentials: %v", err)
			}
			sec = rotatedSec
			deleteRotatedCredsFn = fn
		} else {
			// We have new incoming credentials but we're not rotating. Set them
			// directly for validation below. The existing persisted credentials
			// have already been scheduled for deletion above (if applicable),
			// so we don't need to do it here.
			sec = newSec
		}
	} else {
		if osa.DisableCredentialRotation && !nsa.DisableCredentialRotation {
			// Handle the case where the user enables credential rotation but
			// provides no new credentials. This is an error.
			return nil, status.Errorf(codes.InvalidArgument, "credential rotation enabled with no new credentials provided")
		}
	}

	cl, err := minio.New(nsa.EndpointUrl, &minio.Options{
		Creds:  credentials.NewStaticV4(sec.AccessKeyId, sec.SecretAccessKey, ""),
		Secure: nsa.UseSSL,
		Region: nsa.Region,
	})
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to create minio sdk client: %s", err)
	}

	if p, dryRunErr := dryRun(ctx, cl, newBucket); dryRunErr != nil {
		if dryRunErr.Len() > 0 {
			st := status.New(codes.InvalidArgument, fmt.Sprintf("failed to verify provided minio environment: %v", dryRunErr.Unwrap()))

			st, err = st.WithDetails(&pb.StorageBucketCredentialState{State: p})
			if err != nil {
				st = status.New(codes.InvalidArgument, fmt.Sprintf("failed to verify provided minio environment: %v", dryRunErr.Unwrap()))
			}
			return nil, st.Err()
		}
	}

	persisted, err := structpb.NewStruct(sec.AsMap())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to convert storage attributes to protobuf struct: %s", err)
	}

	// Given that at this point everything is OK with the bucket, we shouldn't
	// let a failure to delete credentials fail the entire process. If we ever
	// establish a way to log non-critical errors in the plugin, log this.
	_ = deleteRotatedCredsFn()
	_ = deleteOldPersistedCredsFn()

	return &pb.OnUpdateStorageBucketResponse{
		Persisted: &storagebuckets.StorageBucketPersisted{Data: persisted},
	}, nil
}

// OnDeleteStorageBucket is a hook that runs when a storage bucket is deleted.
func (sp *StoragePlugin) OnDeleteStorageBucket(ctx context.Context, req *pb.OnDeleteStorageBucketRequest) (*pb.OnDeleteStorageBucketResponse, error) {
	bucket := req.GetBucket()
	if bucket == nil {
		return nil, status.Error(codes.InvalidArgument, "no storage bucket information found")
	}

	sec, err := getStorageSecrets(req.GetPersisted().GetData())
	if err != nil {
		return nil, err
	}

	if !sec.LastRotatedTime.IsZero() {
		sa, err := getStorageAttributes(bucket.GetAttributes())
		if err != nil {
			return nil, err
		}
		ac, err := client.New(sa.EndpointUrl, sec.AccessKeyId, sec.SecretAccessKey, client.WithUseSsl(sa.UseSSL))
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "failed to create client: %v", err)
		}
		err = ac.DeleteServiceAccount(ctx, sec.AccessKeyId)
		if err != nil {
			return nil, status.Errorf(codes.Unknown, "failed to delete minio service account: %v", err)
		}
	}

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

	if !sec.LastRotatedTime.IsZero() {
		// since these are existing secrets, we only want to validate the
		// service account if the credentials have been rotated previously
		err = ensureServiceAccount(ctx, sa, sec)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "failed to ensure service account: %v", err)
		}
	}

	cl, err := minio.New(sa.EndpointUrl, &minio.Options{
		Creds:  credentials.NewStaticV4(sec.AccessKeyId, sec.SecretAccessKey, ""),
		Secure: sa.UseSSL,
		Region: sa.Region,
	})
	if err != nil {
		return nil, status.Errorf(codes.Unknown, "failed to create minio sdk client: %v", err)
	}

	p, dryRunErr := dryRun(ctx, cl, bucket)
	if dryRunErr.Unwrap() != nil {
		st := status.New(codes.FailedPrecondition, fmt.Sprintf("failed to verify provided minio environment: %v", dryRunErr.Unwrap()))

		st, err = st.WithDetails(&pb.StorageBucketCredentialState{State: p})
		if err != nil {
			st = status.New(codes.Unknown, fmt.Sprintf("failed to verify provided minio environment: %v", dryRunErr.Unwrap()))
		}
		return nil, st.Err()
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
		return nil, errorToStatus(codes.Unknown, "failed to create minio sdk client", err, req).Err()
	}

	objKey := path.Join(bucket.GetBucketPrefix(), req.GetKey())
	oi, err := cl.StatObject(ctx, bucket.GetBucketName(), objKey, minio.StatObjectOptions{})
	if err != nil {
		return nil, errorToStatus(codes.Unknown, "failed to stat object", err, req).Err()
	}

	return &pb.HeadObjectResponse{
		ContentLength: oi.Size,
		LastModified:  timestamppb.New(oi.LastModified),
	}, nil
}

// GetObject is a hook that retrieves objects.
func (sp *StoragePlugin) GetObject(req *pb.GetObjectRequest, objServer pb.StoragePluginService_GetObjectServer) error {
	bucket := req.GetBucket()
	if bucket == nil {
		return status.Error(codes.InvalidArgument, "no storage bucket information found")
	}
	if bucket.GetBucketName() == "" {
		return status.Error(codes.InvalidArgument, "storage bucket name is required")
	}

	if req.GetKey() == "" {
		return status.Error(codes.InvalidArgument, "object key is required")
	}

	sa, err := getStorageAttributes(bucket.GetAttributes())
	if err != nil {
		return err
	}

	sec, err := getStorageSecrets(bucket.GetSecrets())
	if err != nil {
		return err
	}

	cl, err := minio.New(sa.EndpointUrl, &minio.Options{
		Creds:  credentials.NewStaticV4(sec.AccessKeyId, sec.SecretAccessKey, ""),
		Secure: sa.UseSSL,
		Region: sa.Region,
	})
	if err != nil {
		return errorToStatus(codes.Unknown, "failed to create minio sdk client", err, req).Err()
	}

	objKey := path.Join(bucket.GetBucketPrefix(), req.GetKey())
	obj, err := cl.GetObject(objServer.Context(), bucket.GetBucketName(), objKey, minio.GetObjectOptions{})
	if err != nil {
		return errorToStatus(codes.Unknown, "failed to get object", err, req).Err()
	}
	defer obj.Close()

	chunkSize := req.GetChunkSize()
	if chunkSize == 0 {
		chunkSize = defaultGetObjectChunkSize
	}

	rd := bufio.NewReader(obj)
	for {
		select {
		case <-objServer.Context().Done():
			return status.Errorf(codes.Canceled, "server context done while streaming: %v", objServer.Context().Err())
		default:
			buffer := make([]byte, chunkSize)
			n, err := rd.Read(buffer)
			if err != nil && err != io.EOF {
				return status.Errorf(codes.Unknown, "failed to read chunk from minio object: %v", err)
			}
			if n > 0 {
				err := objServer.Send(&pb.GetObjectResponse{FileChunk: buffer[:n]})
				if err != nil {
					return status.Errorf(codes.Unknown, "failed to send chunk to client: %v", err)
				}
			}
			if err == io.EOF {
				return nil
			}
		}
	}
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
		return nil, errorToStatus(codes.Internal, "failed to create minio sdk client", err, req).Err()
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
	res, err := cl.PutObject(ctx, bucket.GetBucketName(), key, file, info.Size(), minio.PutObjectOptions{})
	if err != nil {
		return nil, errorToStatus(codes.Internal, "failed to put object into minio", err, req).Err()
	}

	resChecksum := res.ChecksumSHA256
	if resChecksum == "" {
		// We were successful in putting the object but we didn't get a file
		// SHA256 checksum from the server. Given that the call was successful,
		// assume everything went ok and force the checksum to match so we can
		// send it correctly back to Boundary.
		resChecksum = checksum
	}
	if checksum != resChecksum {
		return nil, status.Error(codes.Internal, "mismatched checksum")
	}
	decodedChecksum, err := base64.StdEncoding.DecodeString(resChecksum)
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
	bucket := req.GetBucket()
	if bucket == nil {
		return nil, status.Error(codes.InvalidArgument, "no storage bucket information found")
	}
	if bucket.GetBucketName() == "" {
		return nil, status.Error(codes.InvalidArgument, "storage bucket name is required")
	}

	if req.GetKeyPrefix() == "" {
		return nil, status.Error(codes.InvalidArgument, "key prefix is required")
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
		return nil, errorToStatus(codes.Unknown, "failed to create minio sdk client", err, req).Err()
	}

	prefix := path.Join(bucket.GetBucketPrefix(), req.GetKeyPrefix())
	if strings.HasSuffix(req.GetKeyPrefix(), "/") {
		// path.Join ends by "cleaning" the path, including removing a trailing slash, if
		// it exists. given that a slash is used to denote a folder, it is required here.
		prefix += "/"
	}

	if !req.Recursive {
		if err := cl.RemoveObject(ctx, bucket.GetBucketName(), prefix, minio.RemoveObjectOptions{}); err != nil {
			return nil, errorToStatus(codes.Unknown, "error deleting minio object", err, req).Err()
		}
		return &pb.DeleteObjectsResponse{
			ObjectsDeleted: uint32(1),
		}, nil
	}

	objects := []minio.ObjectInfo{}
	for obj := range cl.ListObjects(ctx, bucket.GetBucketName(), minio.ListObjectsOptions{
		Prefix:    prefix,
		Recursive: true,
	}) {
		if obj.Err != nil {
			return nil, errorToStatus(codes.Unknown, "error iterating minio bucket contents", obj.Err, req).Err()
		}
		objects = append(objects, obj)
	}

	emitter := make(chan minio.ObjectInfo)
	go func() {
		defer close(emitter)
		// we could loop the listobjects respose here, but we want to check all the errs ahead of time
		for _, obj := range objects {
			emitter <- obj
		}
	}()

	removed := 0
	for res := range cl.RemoveObjectsWithResult(ctx, bucket.GetBucketName(), emitter, minio.RemoveObjectsOptions{}) {
		if res.Err != nil {
			return nil, errorToStatus(codes.Unknown, "error deleting minio object(s)", res.Err, req).Err()
		}
		removed++
	}

	return &pb.DeleteObjectsResponse{
		ObjectsDeleted: uint32(removed),
	}, nil
}

// validateWritePermission checks if the plugin has write permission for an object.
func validateWritePermission(ctx context.Context, cl *minio.Client, bucket *storagebuckets.StorageBucket, objectKey string) (*pb.Permission, *multierror.Error) {
	const op = "storage.validateWritePermission"
	var combinedErrors *multierror.Error

	if cl == nil {
		err := fmt.Errorf("%s: minio client is nil", op)
		return &pb.Permission{State: pb.StateType_STATE_TYPE_UNKNOWN, ErrorDetails: err.Error(), CheckedAt: timestamppb.Now()}, multierror.Append(combinedErrors, err)
	}
	if bucket == nil {
		err := fmt.Errorf("%s: storage bucket is nil", op)
		return &pb.Permission{State: pb.StateType_STATE_TYPE_UNKNOWN, ErrorDetails: err.Error(), CheckedAt: timestamppb.Now()}, multierror.Append(combinedErrors, err)
	}

	rd := bytes.NewReader([]byte("hashicorp boundary minio plugin access test"))
	_, err := cl.PutObject(ctx, bucket.GetBucketName(), objectKey, rd, rd.Size(), minio.PutObjectOptions{})
	if err != nil {
		combinedErrors = multierror.Append(combinedErrors, fmt.Errorf("failed to put object at %q: %w", objectKey, err))
		return errorToPermission(err), combinedErrors
	}

	return &pb.Permission{State: pb.StateType_STATE_TYPE_OK, CheckedAt: timestamppb.Now()}, nil
}

// validateReadPermission checks if the plugin has read permission for an object.
func validateReadPermission(ctx context.Context, cl *minio.Client, bucket *storagebuckets.StorageBucket, objectKey string) (*pb.Permission, *multierror.Error) {
	const op = "storage.validateReadPermission"
	var combinedErrors *multierror.Error

	if cl == nil {
		err := fmt.Errorf("%s: minio client is nil", op)
		return &pb.Permission{State: pb.StateType_STATE_TYPE_UNKNOWN, ErrorDetails: err.Error(), CheckedAt: timestamppb.Now()}, multierror.Append(combinedErrors, err)
	}
	if bucket == nil {
		err := fmt.Errorf("%s: storage bucket is nil", op)
		return &pb.Permission{State: pb.StateType_STATE_TYPE_UNKNOWN, ErrorDetails: err.Error(), CheckedAt: timestamppb.Now()}, multierror.Append(combinedErrors, err)
	}
	if objectKey == "" {
		err := fmt.Errorf("%s: object key is empty", op)
		return &pb.Permission{State: pb.StateType_STATE_TYPE_UNKNOWN, ErrorDetails: err.Error(), CheckedAt: timestamppb.Now()}, multierror.Append(combinedErrors, err)
	}

	permission := &pb.Permission{State: pb.StateType_STATE_TYPE_OK}
	_, err := cl.StatObject(ctx, bucket.GetBucketName(), objectKey, minio.StatObjectOptions{})
	if err != nil {
		permission = errorToPermission(err)
		combinedErrors = multierror.Append(combinedErrors, fmt.Errorf("failed to stat object at %q: %w", objectKey, err))
	}

	_, err = cl.GetObject(ctx, bucket.GetBucketName(), objectKey, minio.GetObjectOptions{})
	if err != nil {
		p := errorToPermission(err)
		if permission.GetState() == pb.StateType_STATE_TYPE_OK {
			permission = p
		} else {
			if p != nil && p.GetErrorDetails() != "" {
				permission.ErrorDetails = fmt.Sprintf("%s, %s", permission.GetErrorDetails(), p.GetErrorDetails())
			}
		}
		combinedErrors = multierror.Append(combinedErrors, fmt.Errorf("failed to get object at %q: %w", objectKey, err))
	}

	oiCh := cl.ListObjects(ctx, bucket.GetBucketName(), minio.ListObjectsOptions{Recursive: true})
	for oi := range oiCh {
		if oi.Err != nil {
			if permission.GetState() == pb.StateType_STATE_TYPE_OK {
				permission = errorToPermission(oi.Err)
			} else {
				p := errorToPermission(err)
				if p != nil && p.GetErrorDetails() != "" {
					permission.ErrorDetails = fmt.Sprintf("%s, %s", permission.GetErrorDetails(), p.GetErrorDetails())
				}
			}
			combinedErrors = multierror.Append(fmt.Errorf("failed to list objects in bucket %q: %w", bucket.GetBucketName(), oi.Err))
		}
	}

	if combinedErrors != nil {
		return permission, combinedErrors
	}

	permission.CheckedAt = timestamppb.Now()
	return permission, nil
}

// validateDeletePermission checks if the plugin has delete permission for an object.
func validateDeletePermission(ctx context.Context, cl *minio.Client, bucket *storagebuckets.StorageBucket, objectKey string) (*pb.Permission, *multierror.Error) {
	const op = "storage.validateDeletePermission"

	var combinedErrors *multierror.Error

	if cl == nil {
		err := fmt.Errorf("%s: minio client is nil", op)
		combinedErrors = multierror.Append(combinedErrors, err)
		return &pb.Permission{State: pb.StateType_STATE_TYPE_UNKNOWN, ErrorDetails: err.Error(), CheckedAt: timestamppb.Now()}, combinedErrors
	}
	if bucket == nil {
		err := fmt.Errorf("%s: storage bucket is nil", op)
		combinedErrors = multierror.Append(combinedErrors, err)
		return &pb.Permission{State: pb.StateType_STATE_TYPE_UNKNOWN, ErrorDetails: err.Error(), CheckedAt: timestamppb.Now()}, combinedErrors
	}
	if objectKey == "" {
		err := fmt.Errorf("%s: object key is empty", op)
		combinedErrors = multierror.Append(combinedErrors, err)
		return &pb.Permission{State: pb.StateType_STATE_TYPE_UNKNOWN, ErrorDetails: err.Error(), CheckedAt: timestamppb.Now()}, combinedErrors
	}

	err := cl.RemoveObject(ctx, bucket.GetBucketName(), objectKey, minio.RemoveObjectOptions{})
	if err != nil {
		combinedErrors = multierror.Append(combinedErrors, fmt.Errorf("failed to remove object at %q: %w", objectKey, err))
		return errorToPermission(err), combinedErrors
	}

	return &pb.Permission{State: pb.StateType_STATE_TYPE_OK, CheckedAt: timestamppb.Now()}, nil
}

func dryRun(ctx context.Context, cl *minio.Client, bucket *storagebuckets.StorageBucket) (*pb.Permissions, *multierror.Error) {
	objectKey := path.Join(bucket.GetBucketPrefix(), uuid.New().String())
	permissions := &pb.Permissions{
		Write:  &pb.Permission{State: pb.StateType_STATE_TYPE_UNKNOWN, CheckedAt: timestamppb.Now()},
		Read:   &pb.Permission{State: pb.StateType_STATE_TYPE_UNKNOWN, CheckedAt: timestamppb.Now()},
		Delete: &pb.Permission{State: pb.StateType_STATE_TYPE_UNKNOWN, CheckedAt: timestamppb.Now()},
	}

	var combinedErrors *multierror.Error

	writePermission, writeErr := validateWritePermission(ctx, cl, bucket, objectKey)
	combinedErrors = multierror.Append(combinedErrors, writeErr)
	permissions.Write = writePermission

	readPermission, readErr := validateReadPermission(ctx, cl, bucket, objectKey)
	combinedErrors = multierror.Append(combinedErrors, readErr)
	permissions.Read = readPermission

	deletePermission, deleteErr := validateDeletePermission(ctx, cl, bucket, objectKey)
	combinedErrors = multierror.Append(combinedErrors, deleteErr)
	permissions.Delete = deletePermission

	return permissions, combinedErrors
}

// ensureServiceAccount ensugres the credentials we received belong to a MinIO
// service account. This plugin does not support using user credentials for its
// configuration.
func ensureServiceAccount(ctx context.Context, sa *StorageAttributes, sec *StorageSecrets) error {
	ac, err := client.New(sa.EndpointUrl, sec.AccessKeyId, sec.SecretAccessKey, client.WithUseSsl(sa.UseSSL))
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to create client: %v", err)
	}
	if err := ac.EnsureServiceAccount(ctx, sec.AccessKeyId); err != nil {
		return fmt.Errorf("failed to obtain service account info: %w", err)
	}

	return nil
}

// errorToPermission converts a MinIO error to a plugin permission.
// errorToPermission only handles a subset of MinIO errors that have to do with
// permissions.
// If the MinIO error is not recognized, it returns a permission with an unknown state.
func errorToPermission(err error) *pb.Permission {
	if err == nil {
		return &pb.Permission{}
	}

	errResponse := minio.ToErrorResponse(err)
	switch errResponse.Code {
	// https://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html#ErrorCodeList
	case "AccessDenied":
		fallthrough
	case "InvalidSecurity":
		fallthrough
	case "InvalidAccessKeyId":
		fallthrough
	case "NoSuchBucket":
		return &pb.Permission{State: pb.StateType_STATE_TYPE_ERROR, ErrorDetails: errResponse.Error(), CheckedAt: timestamppb.Now()}
	case "InvalidObjectState":
		fallthrough
	default:
		return &pb.Permission{State: pb.StateType_STATE_TYPE_UNKNOWN, ErrorDetails: errResponse.Error(), CheckedAt: timestamppb.Now()}
	}
}

// errorToStatus converts an error to a gRPC status with the plugin permission
// attached.
// If the permission error is not recognized, a gRPC status will be returned
// with an code and error message passed in.
func errorToStatus(code codes.Code, msg string, err error, req any) *status.Status {
	if err == nil {
		// If we see this status, it means this function was called with a nil
		// err. This is odd and should probably be investigated.
		return status.New(code, fmt.Sprintf("%s: no error from storage service provider", msg))
	}

	errResponse := minio.ToErrorResponse(err)
	switch errResponse.Code {
	// https://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html#ErrorCodeList
	case "RequestTimeout":
		return status.New(codes.DeadlineExceeded, fmt.Sprintf("%s: timeout exceeded when communicating with storage service provider", msg))
	case "SlowDown":
		return status.New(codes.Unavailable, fmt.Sprintf("%s: received a throttling response from storage service provider", msg))
	case "BadDigest":
		return status.New(codes.Aborted, fmt.Sprintf("%s: storage checksum mismatch", msg))
	case "NoSuchBucket":
		return status.New(codes.NotFound, fmt.Sprintf("%s: specified storage bucket does not exist", msg))
	case "NoSuchKey":
		return status.New(codes.NotFound, fmt.Sprintf("%s: specified object does not exist", msg))
	}
	if errResponse.StatusCode == 400 {
		// catch-all for various different bad-request related errors
		return status.New(codes.InvalidArgument, fmt.Sprintf("%s: received a bad request response from storage service provider: %v", msg, err))
	}

	// for all other errors, we can parse as permission state errors
	permission := errorToPermission(err)
	state := &pb.StorageBucketCredentialState{State: &pb.Permissions{}}

	// we can use the request type to determine what kind of response we should return
	switch req.(type) {
	case pb.HeadObjectRequest, *pb.HeadObjectRequest:
		state.State.Read = permission
	case pb.GetObjectRequest, *pb.GetObjectRequest:
		state.State.Read = permission
	case pb.PutObjectRequest, *pb.PutObjectRequest:
		state.State.Write = permission
	case pb.DeleteObjectsRequest, *pb.DeleteObjectsRequest:
		state.State.Delete = permission
	}

	st, err := status.New(code, fmt.Sprintf("%s: %s", msg, err)).WithDetails(state)
	if err != nil {
		st = status.New(code, fmt.Sprintf("%s: %s", msg, err))
	}
	return st
}
