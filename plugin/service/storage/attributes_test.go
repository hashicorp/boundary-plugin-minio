// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package storage

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestGetStorageAttributes(t *testing.T) {
	tests := []struct {
		name                 string
		inAttributes         *structpb.Struct
		expStorageAttributes *StorageAttributes
		expErrMsg            string
	}{
		{
			name:         "nilAttributes",
			inAttributes: nil,
			expErrMsg:    "empty attributes input",
		},
		{
			name:         "nilAttributesFields",
			inAttributes: &structpb.Struct{Fields: nil},
			expErrMsg:    "empty attributes input",
		},
		{
			name:         "emptyAttributesFields",
			inAttributes: &structpb.Struct{Fields: map[string]*structpb.Value{}},
			expErrMsg:    "empty attributes input",
		},
		{
			name: "emptyEndpointUrlAttribute",
			inAttributes: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstEndpointUrl: structpb.NewStringValue(""),
				},
			},
			expErrMsg: "attributes.endpoint_url: value \"endpoint_url\" cannot be empty",
		},
		{
			name: "endpointUrlAttributeBadType",
			inAttributes: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstEndpointUrl: structpb.NewBoolValue(true),
				},
			},
			expErrMsg: "attributes.endpoint_url: unexpected type for value \"endpoint_url\": want string, got bool",
		},
		{
			name: "badEndpointUrlAttributeFormat",
			inAttributes: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstEndpointUrl: structpb.NewStringValue("bad://foo.bar"),
				},
			},
			expErrMsg: "attributes.endpoint_url.format: unknown protocol, should be http:// or https://",
		},
		{
			name: "regionAttributeBadType",
			inAttributes: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstEndpointUrl: structpb.NewStringValue("http://foo.bar"),
					ConstRegion:      structpb.NewBoolValue(true),
				},
			},
			expErrMsg: "attributes.region: unexpected type for value \"region\": want string, got bool",
		},
		{
			name: "unknownAttribute",
			inAttributes: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstEndpointUrl: structpb.NewStringValue("http://foo.bar"),
					ConstRegion:      structpb.NewStringValue("us-east-1"),
					"foo":            structpb.NewStringValue("bar"),
				},
			},
			expErrMsg: "attributes.foo: unrecognized field",
		},
		{
			name: "noEndpointUrlAttribute",
			inAttributes: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"foo": structpb.NewStringValue("bar"),
				},
			},
			expErrMsg: "attributes.endpoint_url: missing required value \"endpoint_url\"",
		},
		{
			name: "successWithNoSSL",
			inAttributes: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstEndpointUrl: structpb.NewStringValue("http://foo.bar"),
					ConstRegion:      structpb.NewStringValue("us-east-1"),
				},
			},
			expStorageAttributes: &StorageAttributes{
				EndpointUrl: "foo.bar",
				Region:      "us-east-1",
				UseSSL:      false,
			},
		},
		{
			name: "successWithSSL",
			inAttributes: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstEndpointUrl: structpb.NewStringValue("https://foo.bar"),
					ConstRegion:      structpb.NewStringValue("us-east-1"),
				},
			},
			expStorageAttributes: &StorageAttributes{
				EndpointUrl: "foo.bar",
				Region:      "us-east-1",
				UseSSL:      true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sa, err := getStorageAttributes(tt.inAttributes)
			if tt.expErrMsg != "" {
				require.ErrorContains(t, err, tt.expErrMsg)
				require.Nil(t, sa)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, sa)
			require.EqualValues(t, tt.expStorageAttributes, sa)
		})
	}
}

func TestGetStorageSecrets(t *testing.T) {
	tests := []struct {
		name              string
		inSecrets         *structpb.Struct
		expStorageSecrets *StorageSecrets
		expErrMsg         string
	}{
		{
			name:      "nilSecrets",
			inSecrets: nil,
			expErrMsg: "empty secrets input",
		},
		{
			name:      "nilSecretsFields",
			inSecrets: &structpb.Struct{Fields: nil},
			expErrMsg: "empty secrets input",
		},
		{
			name:      "emptySecretsFields",
			inSecrets: &structpb.Struct{Fields: map[string]*structpb.Value{}},
			expErrMsg: "empty secrets input",
		},
		{
			name: "noAccessKeyIdSecret",
			inSecrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstSecretAccessKey: structpb.NewStringValue("bar"),
				},
			},
			expErrMsg: "secrets.access_key_id: missing required value \"access_key_id\"",
		},
		{
			name: "emptyAccessKeyIdSecret",
			inSecrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstAccessKeyId:     structpb.NewStringValue(""),
					ConstSecretAccessKey: structpb.NewStringValue("bar"),
				},
			},
			expErrMsg: "secrets.access_key_id: value \"access_key_id\" cannot be empty",
		},
		{
			name: "accessKeyIdSecretBadType",
			inSecrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstAccessKeyId:     structpb.NewBoolValue(true),
					ConstSecretAccessKey: structpb.NewStringValue("bar"),
				},
			},
			expErrMsg: "secrets.access_key_id: unexpected type for value \"access_key_id\": want string, got bool",
		},
		{
			name: "noSecretAccessKeySecret",
			inSecrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstAccessKeyId: structpb.NewStringValue("bar"),
				},
			},
			expErrMsg: "secrets.secret_access_key: missing required value \"secret_access_key\"",
		},
		{
			name: "emptySecretAccessKeySecret",
			inSecrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstAccessKeyId:     structpb.NewStringValue("bar"),
					ConstSecretAccessKey: structpb.NewStringValue(""),
				},
			},
			expErrMsg: "secrets.secret_access_key: value \"secret_access_key\" cannot be empty",
		},
		{
			name: "secretAccessKeySecretBadType",
			inSecrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstAccessKeyId:     structpb.NewStringValue("bar"),
					ConstSecretAccessKey: structpb.NewBoolValue(true),
				},
			},
			expErrMsg: "secrets.secret_access_key: unexpected type for value \"secret_access_key\": want string, got bool",
		},
		{
			name: "unknownSecret",
			inSecrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstAccessKeyId:     structpb.NewStringValue("bar"),
					ConstSecretAccessKey: structpb.NewStringValue("bar"),
					"foo":                structpb.NewStringValue("bar"),
				},
			},
			expErrMsg: "secrets.foo: unrecognized field",
		},
		{
			name: "success",
			inSecrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstAccessKeyId:     structpb.NewStringValue("foo"),
					ConstSecretAccessKey: structpb.NewStringValue("bar"),
				},
			},
			expStorageSecrets: &StorageSecrets{
				AccessKeyId:     "foo",
				SecretAccessKey: "bar",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sa, err := getStorageSecrets(tt.inSecrets)
			if tt.expErrMsg != "" {
				require.ErrorContains(t, err, tt.expErrMsg)
				require.Nil(t, sa)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, sa)
			require.EqualValues(t, tt.expStorageSecrets, sa)
		})
	}
}

func TestStorageSecretsAsMap(t *testing.T) {
	tests := []struct {
		name   string
		in     *StorageSecrets
		expMap map[string]any
	}{
		{
			name: "completeObject",
			in: &StorageSecrets{
				AccessKeyId:     "access_key_id_value",
				SecretAccessKey: "secret_access_key_value",
			},
			expMap: map[string]any{
				"access_key_id":     "access_key_id_value",
				"secret_access_key": "secret_access_key_value",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := tt.in.AsMap()
			require.EqualValues(t, tt.expMap, m)
		})
	}
}
