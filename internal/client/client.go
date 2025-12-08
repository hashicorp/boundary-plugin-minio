// Copyright IBM Corp. 2024, 2025
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/hashicorp/boundary-plugin-minio/madmin"
	"github.com/minio/minio-go/v7/pkg/signer"
)

const adminPrefix = "/minio/admin/v3"

// AddServiceAccountReq contains the values used by the plugin when creating a minio service account
type AddServiceAccountReq struct {
	// Policy to apply to service account
	Policy json.RawMessage `json:"policy,omitempty"`
	// Name for this access key
	Name string `json:"name,omitempty"`
	// Description for this access key
	Description string `json:"description,omitempty"`
}

// AddServiceAccountResp contains the credentials associated with the added service account
type AddServiceAccountResp struct {
	Cred Credential `json:"credentials"`
}

// Credential contains a minio AccessKeyId and SecretAccessKey
type Credential struct {
	AccessKeyId     string `json:"accessKey,omitempty"`
	SecretAccessKey string `json:"secretKey,omitempty"`
}

// MinioError contains the error message from failed admin API requests
type MinioError struct {
	Message string `json:"message,omitempty"`
}

// Client is used to access Minio admin API
type Client struct {
	endpointUrl     *url.URL
	accessKeyId     string
	secretAccessKey string
}

// getOpts - iterate the inbound Options and return a struct
func getOpts(opt ...Option) options {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

// Option - how options are passed as arguments
type Option func(*options)

// options = how options are represented
type options struct {
	withUseSsl bool
}

func getDefaultOptions() options {
	return options{}
}

// WithUseSsl provides an Option to use SSL.
func WithUseSsl(b bool) Option {
	return func(o *options) {
		o.withUseSsl = b
	}
}

// New creates a Client that can be used to access Minio admin API
func New(endpointUrl, accessKeyId, secretAccessKey string, opt ...Option) (*Client, error) {
	opts := getOpts(opt...)
	url, err := madmin.GetEndpointURL(endpointUrl, opts.withUseSsl)
	if err != nil {
		return nil, err
	}
	return &Client{endpointUrl: url, accessKeyId: accessKeyId, secretAccessKey: secretAccessKey}, nil
}

// DeleteServiceAccount deletes the provided serviceAccount
func (c *Client) DeleteServiceAccount(ctx context.Context, serviceAccount string) error {
	// construct the url
	url := c.endpointUrl.JoinPath(adminPrefix, "delete-service-account")
	query := url.Query()
	query.Set("accessKey", serviceAccount)
	url.RawQuery = query.Encode()

	// create the request
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Get sha256 for request header
	sum := sha256.Sum256(nil)
	req.Header.Set("X-Amz-Content-Sha256", hex.EncodeToString(sum[:]))

	// Sign request as documented
	// https://min.io/docs/minio/kubernetes/upstream/administration/identity-access-management.html
	req = signer.SignV4(*req, c.accessKeyId, c.secretAccessKey, "", "")

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check response status code
	if resp.StatusCode != http.StatusNoContent {
		// expected no content response, unmarshal resp body for error message
		respBody, _ := io.ReadAll(resp.Body)
		if len(respBody) == 0 {
			return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
		}

		errResp := &MinioError{}
		if err := json.Unmarshal(respBody, &errResp); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}
		return errors.New(errResp.Message)
	}

	return nil
}

// AddServiceAccount adds a service account to the minio server
func (c *Client) AddServiceAccount(ctx context.Context, in AddServiceAccountReq) (Credential, error) {
	// construct the url
	url := c.endpointUrl.JoinPath(adminPrefix, "add-service-account")

	// marshal and encrypt data payload
	data, err := json.Marshal(in)
	if err != nil {
		return Credential{}, err
	}

	// Minio encrypts streaming data as described https://blog.min.io/frictionless-encryption/
	payload, err := madmin.EncryptData(c.secretAccessKey, data)
	if err != nil {
		return Credential{}, err
	}

	// create the request
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url.String(), bytes.NewReader(payload))
	if err != nil {
		return Credential{}, fmt.Errorf("failed to create request: %w", err)
	}

	// Get sha256 for request header
	sum := sha256.Sum256(payload)
	req.Header.Set("X-Amz-Content-Sha256", hex.EncodeToString(sum[:]))
	req.Header.Set("Content-Type", "application/json")

	// Sign request as documented
	// https://min.io/docs/minio/kubernetes/upstream/administration/identity-access-management.html
	req = signer.SignV4(*req, c.accessKeyId, c.secretAccessKey, "", "")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return Credential{}, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// did not get ok, unmarshal resp body for error message
		respBody, _ := io.ReadAll(resp.Body)
		if len(respBody) == 0 {
			return Credential{}, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
		}

		errResp := &MinioError{}
		if err := json.Unmarshal(respBody, &errResp); err != nil {
			return Credential{}, fmt.Errorf("failed to parse response: %w", err)
		}
		return Credential{}, errors.New(errResp.Message)
	}

	// got resp lets decrypt it
	result, err := madmin.DecryptData(c.secretAccessKey, resp.Body)
	addResp := &AddServiceAccountResp{}
	if err := json.Unmarshal(result, &addResp); err != nil {
		return Credential{}, fmt.Errorf("failed to parse response: %w", err)
	}

	return addResp.Cred, nil
}

// EnsureServiceAccount true if the account is a service account
func (c *Client) EnsureServiceAccount(ctx context.Context, serviceAccount string) error {
	// construct the url
	url := c.endpointUrl.JoinPath(adminPrefix, "info-service-account")
	query := url.Query()
	query.Set("accessKey", serviceAccount)
	url.RawQuery = query.Encode()

	// create the request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// get sha256 for request header
	sum := sha256.Sum256(nil)
	req.Header.Set("X-Amz-Content-Sha256", hex.EncodeToString(sum[:]))

	// sign request as documented
	// https://min.io/docs/minio/kubernetes/upstream/administration/identity-access-management.html
	req = signer.SignV4(*req, c.accessKeyId, c.secretAccessKey, "", "")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// did not get ok, unmarshal resp body for error message
		respBody, _ := io.ReadAll(resp.Body)
		if len(respBody) == 0 {
			return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
		}

		errResp := &MinioError{}
		if err := json.Unmarshal(respBody, &errResp); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}
		return errors.New(errResp.Message)
	}

	return nil
}
