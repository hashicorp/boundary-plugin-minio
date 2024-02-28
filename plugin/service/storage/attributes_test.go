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
		inSecrets            *structpb.Struct
		expStorageAttributes *StorageAttributes
		expErrMsg            string
	}{
		{
			name:         "nilAttributes",
			inAttributes: nil,
			inSecrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"foo": structpb.NewStringValue("bar"),
				},
			},
			expErrMsg: "empty attributes input",
		},
		{
			name:         "nilAttributesFields",
			inAttributes: &structpb.Struct{Fields: nil},
			inSecrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"foo": structpb.NewStringValue("bar"),
				},
			},
			expErrMsg: "empty attributes input",
		},
		{
			name:         "emptyAttributesFields",
			inAttributes: &structpb.Struct{Fields: map[string]*structpb.Value{}},
			inSecrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"foo": structpb.NewStringValue("bar"),
				},
			},
			expErrMsg: "empty attributes input",
		},
		{
			name: "nilSecrets",
			inAttributes: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"foo": structpb.NewStringValue("bar"),
				},
			},
			inSecrets: nil,
			expErrMsg: "empty secrets input",
		},
		{
			name: "nilSecretsFields",
			inAttributes: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"foo": structpb.NewStringValue("bar"),
				},
			},
			inSecrets: &structpb.Struct{Fields: nil},
			expErrMsg: "empty secrets input",
		},
		{
			name: "emptySecretsFields",
			inAttributes: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"foo": structpb.NewStringValue("bar"),
				},
			},
			inSecrets: &structpb.Struct{Fields: map[string]*structpb.Value{}},
			expErrMsg: "empty secrets input",
		},
		{
			name: "noEndpointUrlAttribute",
			inAttributes: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"foo": structpb.NewStringValue("bar"),
				},
			},
			inSecrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstAccessKeyId:     structpb.NewStringValue("bar"),
					ConstSecretAccessKey: structpb.NewStringValue("bar"),
				},
			},
			expErrMsg: "attributes.endpoint_url: missing required value \"endpoint_url\"",
		},
		{
			name: "emptyEndpointUrlAttribute",
			inAttributes: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstEndpointUrl: structpb.NewStringValue(""),
				},
			},
			inSecrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstAccessKeyId:     structpb.NewStringValue("bar"),
					ConstSecretAccessKey: structpb.NewStringValue("bar"),
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
			inSecrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstAccessKeyId:     structpb.NewStringValue("bar"),
					ConstSecretAccessKey: structpb.NewStringValue("bar"),
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
			inSecrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstAccessKeyId:     structpb.NewStringValue("bar"),
					ConstSecretAccessKey: structpb.NewStringValue("bar"),
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
			inSecrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstAccessKeyId:     structpb.NewStringValue("bar"),
					ConstSecretAccessKey: structpb.NewStringValue("bar"),
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
			inSecrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstAccessKeyId:     structpb.NewStringValue("bar"),
					ConstSecretAccessKey: structpb.NewStringValue("bar"),
				},
			},
			expErrMsg: "attributes.foo: unrecognized field",
		},
		{
			name: "noAccessKeyIdSecret",
			inAttributes: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstEndpointUrl: structpb.NewStringValue("http://foo.bar"),
					ConstRegion:      structpb.NewStringValue("us-east-1"),
				},
			},
			inSecrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstSecretAccessKey: structpb.NewStringValue("bar"),
				},
			},
			expErrMsg: "secrets.access_key_id: missing required value \"access_key_id\"",
		},
		{
			name: "emptyAccessKeyIdSecret",
			inAttributes: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstEndpointUrl: structpb.NewStringValue("http://foo.bar"),
					ConstRegion:      structpb.NewStringValue("us-east-1"),
				},
			},
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
			inAttributes: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstEndpointUrl: structpb.NewStringValue("http://foo.bar"),
					ConstRegion:      structpb.NewStringValue("us-east-1"),
				},
			},
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
			inAttributes: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstEndpointUrl: structpb.NewStringValue("http://foo.bar"),
					ConstRegion:      structpb.NewStringValue("us-east-1"),
				},
			},
			inSecrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstAccessKeyId: structpb.NewStringValue("bar"),
				},
			},
			expErrMsg: "secrets.secret_access_key: missing required value \"secret_access_key\"",
		},
		{
			name: "emptySecretAccessKeySecret",
			inAttributes: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstEndpointUrl: structpb.NewStringValue("http://foo.bar"),
					ConstRegion:      structpb.NewStringValue("us-east-1"),
				},
			},
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
			inAttributes: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstEndpointUrl: structpb.NewStringValue("http://foo.bar"),
					ConstRegion:      structpb.NewStringValue("us-east-1"),
				},
			},
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
			inAttributes: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstEndpointUrl: structpb.NewStringValue("http://foo.bar"),
					ConstRegion:      structpb.NewStringValue("us-east-1"),
				},
			},
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
			name: "successWithNoSSL",
			inAttributes: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstEndpointUrl: structpb.NewStringValue("http://foo.bar"),
					ConstRegion:      structpb.NewStringValue("us-east-1"),
				},
			},
			inSecrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstAccessKeyId:     structpb.NewStringValue("foo"),
					ConstSecretAccessKey: structpb.NewStringValue("bar"),
				},
			},
			expStorageAttributes: &StorageAttributes{
				AccessKeyId:     "foo",
				SecretAccessKey: "bar",
				EndpointUrl:     "foo.bar",
				Region:          "us-east-1",
				UseSSL:          false,
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
			inSecrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstAccessKeyId:     structpb.NewStringValue("foo"),
					ConstSecretAccessKey: structpb.NewStringValue("bar"),
				},
			},
			expStorageAttributes: &StorageAttributes{
				AccessKeyId:     "foo",
				SecretAccessKey: "bar",
				EndpointUrl:     "foo.bar",
				Region:          "us-east-1",
				UseSSL:          true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sa, err := getStorageAttributes(tt.inAttributes, tt.inSecrets)
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

func TestStorageAttributesSecretsToMap(t *testing.T) {
	tests := []struct {
		name   string
		in     *StorageAttributes
		expMap map[string]any
	}{
		{
			name: "completeObject",
			in: &StorageAttributes{
				AccessKeyId:     "access_key_id_value",
				SecretAccessKey: "secret_access_key_value",
				EndpointUrl:     "endpoint_url_value",
				Region:          "region_value",
				UseSSL:          true,
			},
			expMap: map[string]any{
				"access_key_id":     "access_key_id_value",
				"secret_access_key": "secret_access_key_value",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := tt.in.SecretsToMap()
			require.EqualValues(t, tt.expMap, m)
		})
	}
}
