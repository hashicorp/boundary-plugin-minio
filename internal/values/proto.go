// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package values

import (
	"fmt"

	"google.golang.org/protobuf/types/known/structpb"
)

// GetStringValue returns a string value and no error if the given key is found
// in the provided proto struct input. An error is returned if the key is not
// found or the value type is not a string. An error is returned if the
// parameter argument "required" is set to true and the value from the proto
// struct input is empty.
func GetStringValue(in *structpb.Struct, k string, required bool) (string, error) {
	mv := in.GetFields()
	v, ok := mv[k]
	if !ok {
		if required {
			return "", fmt.Errorf("missing required value %q", k)
		}

		return "", nil
	}

	s, ok := v.AsInterface().(string)
	if !ok {
		return "", fmt.Errorf("unexpected type for value %q: want string, got %T", k, v.AsInterface())
	}

	if s == "" && required {
		return "", fmt.Errorf("value %q cannot be empty", k)
	}

	return s, nil
}

// StructFields returns a map[string]struct{} of the proto struct input.
func StructFields(s *structpb.Struct) map[string]struct{} {
	m := make(map[string]struct{}, len(s.GetFields()))
	for k := range s.GetFields() {
		m[k] = struct{}{}
	}

	return m
}
