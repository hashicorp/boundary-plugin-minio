// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
