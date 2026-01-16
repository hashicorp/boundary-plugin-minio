// Copyright IBM Corp. 2024, 2025
// SPDX-License-Identifier: MPL-2.0

package errors

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInvalidArgumentError(t *testing.T) {
	// No error message.
	err := InvalidArgumentError("", map[string]string{
		"foo_key": "foo_value",
		"bar_key": "bar_value",
		"baz_key": "baz_value",
	})
	require.EqualError(t, err, "rpc error: code = InvalidArgument desc = : [bar_key: bar_value, baz_key: baz_value, foo_key: foo_value]")

	// Nil fields
	err = InvalidArgumentError("error message", nil)
	require.EqualError(t, err, "rpc error: code = InvalidArgument desc = error message")

	// Empty fields.
	err = InvalidArgumentError("error message", map[string]string{})
	require.EqualError(t, err, "rpc error: code = InvalidArgument desc = error message")

	// Everything.
	err = InvalidArgumentError("error message", map[string]string{
		"foo_key": "foo_value",
		"bar_key": "bar_value",
		"baz_key": "baz_value",
	})
	require.EqualError(t, err, "rpc error: code = InvalidArgument desc = error message: [bar_key: bar_value, baz_key: baz_value, foo_key: foo_value]")

}
