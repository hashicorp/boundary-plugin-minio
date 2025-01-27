// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package madmin

import "net/url"

// GetEndpointURL is a wrapper added by Hashicorp in 2025 to export the getEndpointURL
// function in utils.go
func GetEndpointURL(endpoint string, secure bool) (*url.URL, error) {
	return getEndpointURL(endpoint, secure)
}
