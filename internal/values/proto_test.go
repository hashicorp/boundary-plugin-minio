// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package values

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestGetStringValue(t *testing.T) {
	cases := []struct {
		name        string
		in          map[string]any
		key         string
		required    bool
		expected    string
		expectedErr string
	}{
		{
			name:        "required missing",
			in:          map[string]any{},
			key:         "foo",
			required:    true,
			expectedErr: "missing required value \"foo\"",
		},
		{
			name:     "optional missing",
			in:       map[string]any{},
			key:      "foo",
			expected: "",
		},
		{
			name: "non-string value",
			in: map[string]any{
				"foo": 1,
			},
			key:         "foo",
			expectedErr: "unexpected type for value \"foo\": want string, got float64",
		},
		{
			name: "required empty",
			in: map[string]any{
				"foo": "",
			},
			key:         "foo",
			required:    true,
			expectedErr: "value \"foo\" cannot be empty",
		},
		{
			name: "good",
			in: map[string]any{
				"foo": "bar",
			},
			key:      "foo",
			expected: "bar",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)

			input, err := structpb.NewStruct(tc.in)
			require.NoError(err)

			actual, err := GetStringValue(input, tc.key, tc.required)
			if tc.expectedErr != "" {
				require.EqualError(err, tc.expectedErr)
				return
			}

			require.NoError(err)
			require.Equal(tc.expected, actual)
		})
	}
}
