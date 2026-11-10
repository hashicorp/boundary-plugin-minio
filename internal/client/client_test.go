// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/boundary-plugin-minio/madmin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAddServiceAccountResponse(t *testing.T) {
	t.Parallel()
	const password = "test-password"
	validResponse := []byte(`{"credentials":{"accessKey":"test-access-key","secretKey":"test-secret-key"}}`)
	tests := []struct {
		name          string
		plaintext     []byte
		password      string
		emptyResponse bool
		wantErr       string
		wantCause     error
	}{
		{name: "success", plaintext: validResponse, password: password},
		{name: "truncated ciphertext", emptyResponse: true, wantErr: "failed to decrypt response", wantCause: io.EOF},
		{name: "wrong password", plaintext: validResponse, password: "wrong-password", wantErr: "failed to decrypt response", wantCause: madmin.ErrMaliciousData},
		{name: "invalid JSON", plaintext: []byte("not JSON"), password: password, wantErr: "failed to parse response"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var response []byte
			if !test.emptyResponse {
				var err error
				response, err = madmin.EncryptData(test.password, test.plaintext)
				require.NoError(t, err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				assert.Equal(t, http.MethodPut, request.Method)
				assert.Equal(t, adminPrefix+"/add-service-account", request.URL.Path)
				_, _ = writer.Write(response)
			}))
			defer server.Close()
			client, err := New(strings.TrimPrefix(server.URL, "http://"), "test-access-key", password)
			require.NoError(t, err)
			credential, err := client.AddServiceAccount(context.Background(), AddServiceAccountReq{})
			if test.wantErr != "" {
				require.ErrorContains(t, err, test.wantErr)
				assert.Empty(t, credential)
				if test.wantCause != nil {
					assert.ErrorIs(t, err, test.wantCause)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, Credential{AccessKeyId: "test-access-key", SecretAccessKey: "test-secret-key"}, credential)
		})
	}
}

func TestNew(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	type args struct {
		endpointUrl     string
		accessKeyId     string
		secretAccessKey string
		opt             []Option
	}
	tests := []struct {
		name    string
		args    args
		wantUrl string
		wantErr bool
	}{
		{
			name:    "fully qualified path",
			args:    args{endpointUrl: "https://test.com"},
			wantErr: true,
		},
		{
			name: "no ssl",
			args: args{
				endpointUrl:     "test.com",
				accessKeyId:     "username",
				secretAccessKey: "password",
			},
			wantUrl: "http://test.com",
		},
		{
			name: "with ssl",
			args: args{
				endpointUrl:     "test.com",
				accessKeyId:     "username",
				secretAccessKey: "password",
				opt:             []Option{WithUseSsl(true)},
			},
			wantUrl: "https://test.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.args.endpointUrl, tt.args.accessKeyId, tt.args.secretAccessKey, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			require.NotNil(got)
			assert.Equal(tt.wantUrl, got.endpointUrl.String())
			assert.Equal(tt.args.accessKeyId, got.accessKeyId)
			assert.Equal(tt.args.secretAccessKey, got.secretAccessKey)
		})
	}
}

func Test_getOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithUseSsl", func(t *testing.T) {
		testOpts := getDefaultOptions()
		assert.Equal(t, false, testOpts.withUseSsl)

		testOpts = getOpts()
		assert.Equal(t, false, testOpts.withUseSsl)

		testOpts = getOpts(WithUseSsl(true))
		assert.Equal(t, true, testOpts.withUseSsl)
	})
}
