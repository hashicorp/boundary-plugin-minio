// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package storage

import (
	"fmt"
	"strings"

	"github.com/hashicorp/boundary-plugin-minio/internal/errors"
	"github.com/hashicorp/boundary-plugin-minio/internal/values"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	ConstEndpointUrl     = "endpoint_url"
	ConstAccessKeyId     = "access_key_id"
	ConstSecretAccessKey = "secret_access_key"
	ConstRegion          = "region"
)

type StorageAttributes struct {
	// AccessKeyId is the MinIO Access Key Id. This field is required and comes
	// from user input.
	AccessKeyId string
	// SecretAccessKey is the MinIO Secret Access Key. This field is required
	// and comes from user input.
	SecretAccessKey string
	// EndpointUrl is the MinIO server URL. This field is required and comes
	// from user input.
	EndpointUrl string
	// Region is the MinIO region. This field is optional and comes from user
	// input.
	Region string
	// UseSSL determines if the MinIO SDK will use SSL when communicating with
	// the server. This field is determined based on the endpoint URL prefix.
	UseSSL bool
}

// ToMap returns a map StorageAttributes's secret fields as a map.
func (sa *StorageAttributes) SecretsToMap() map[string]any {
	return map[string]any{
		ConstAccessKeyId:     sa.AccessKeyId,
		ConstSecretAccessKey: sa.SecretAccessKey,
	}
}

func getStorageAttributes(inAttributes *structpb.Struct, inSecrets *structpb.Struct) (*StorageAttributes, error) {
	if inAttributes == nil || inAttributes.GetFields() == nil || len(inAttributes.GetFields()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "empty attributes input")
	}
	if inSecrets == nil || inSecrets.GetFields() == nil || len(inSecrets.GetFields()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "empty secrets input")
	}

	badFields := make(map[string]string)

	unknownAttrFields := values.StructFields(inAttributes)
	endpointUrl, err := values.GetStringValue(inAttributes, ConstEndpointUrl, true)
	if err != nil {
		badFields[fmt.Sprintf("attributes.%s", ConstEndpointUrl)] = err.Error()
	}
	delete(unknownAttrFields, ConstEndpointUrl)

	// The MinIO SDK doesn't want a fully-qualified URL, so we have to strip it
	// here and transform it to a combination of URL + useSSL.
	useSSL := true // Assume SSL by default.
	if strings.HasPrefix(endpointUrl, "https://") {
		endpointUrl = strings.TrimPrefix(endpointUrl, "https://")
	} else if strings.HasPrefix(endpointUrl, "http://") {
		useSSL = false
		endpointUrl = strings.TrimPrefix(endpointUrl, "http://")
	} else {
		badFields[fmt.Sprintf("attributes.%s.format", ConstEndpointUrl)] = "unknown protocol, should be http:// or https://"
	}

	region, err := values.GetStringValue(inAttributes, ConstRegion, false)
	if err != nil {
		badFields[fmt.Sprintf("attributes.%s", ConstRegion)] = err.Error()
	}
	delete(unknownAttrFields, ConstRegion)

	for s := range unknownAttrFields {
		badFields[fmt.Sprintf("attributes.%s", s)] = "unrecognized field"
	}

	unknownSecretFields := values.StructFields(inSecrets)
	accessKeyId, err := values.GetStringValue(inSecrets, ConstAccessKeyId, true)
	if err != nil {
		badFields[fmt.Sprintf("secrets.%s", ConstAccessKeyId)] = err.Error()
	}
	delete(unknownSecretFields, ConstAccessKeyId)

	secretAccessKey, err := values.GetStringValue(inSecrets, ConstSecretAccessKey, true)
	if err != nil {
		badFields[fmt.Sprintf("secrets.%s", ConstSecretAccessKey)] = err.Error()
	}
	delete(unknownSecretFields, ConstSecretAccessKey)

	for s := range unknownSecretFields {
		badFields[fmt.Sprintf("secrets.%s", s)] = "unrecognized field"
	}

	if len(badFields) > 0 {
		return nil, errors.InvalidArgumentError("invalid or unrecognized attributes/secrets found", badFields)
	}
	return &StorageAttributes{
		AccessKeyId:     accessKeyId,
		SecretAccessKey: secretAccessKey,
		EndpointUrl:     endpointUrl,
		Region:          region,
		UseSSL:          useSSL,
	}, nil
}
