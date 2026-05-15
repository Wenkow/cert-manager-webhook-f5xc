package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	defaultServer    = "console.ves.volterra.io"
	defaultTimeout   = 30 * time.Second
	rrsetPathPattern = "/api/config/dns/namespaces/system/dns_zones/%s/rrsets/%s"
)

// Retry settings for transient 503 errors (F5 XC code 14: "Previous DNS zone change is pending").
// These are vars (not consts) so tests can override them.
const retryableCode = 14

var (
	retryInterval   = 2 * time.Second
	retryMaxElapsed = 60 * time.Second
)

// Client is an HTTP client for the F5 Distributed Cloud RRSet API.
type Client struct {
	baseURL    string
	auth       Authenticator
	httpClient *http.Client
}

// NewClient creates a new F5 XC API client.
// tenantName is the F5 XC tenant (e.g. "acme").
// server is the base domain (defaults to "console.ves.volterra.io").
func NewClient(tenantName, server string, auth Authenticator) (*Client, error) {
	if tenantName == "" {
		return nil, errors.New("f5xc: tenant name is required")
	}
	if auth == nil {
		return nil, errors.New("f5xc: authenticator is required")
	}
	if server == "" {
		server = defaultServer
	}
	return &Client{
		baseURL:    fmt.Sprintf("https://%s.%s", tenantName, server),
		auth:       auth,
		httpClient: &http.Client{Timeout: defaultTimeout},
	}, nil
}

// CreateRRSet creates a new DNS record set via POST.
// Retries on transient 503 errors.
func (c *Client) CreateRRSet(ctx context.Context, zone, group string, rrset RRSet) (*APIRRSet, error) {
	path := fmt.Sprintf(rrsetPathPattern, zone, group)
	body := APIRRSet{
		DNSZoneName: zone,
		GroupName:   group,
		RRSet:       rrset,
	}
	var result APIRRSet
	if err := c.doWithRetry(ctx, http.MethodPost, path, body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetRRSet retrieves a DNS record set by name and type.
// Returns (nil, nil) if the record is not found (404).
func (c *Client) GetRRSet(ctx context.Context, zone, group, name, recordType string) (*APIRRSet, error) {
	path := fmt.Sprintf(rrsetPathPattern+"/%s/%s", zone, group, name, recordType)
	var result APIRRSet
	if err := c.do(ctx, http.MethodGet, path, nil, &result); err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &result, nil
}

// ReplaceRRSet updates an existing DNS record set via PUT.
// Retries on transient 503 errors.
func (c *Client) ReplaceRRSet(ctx context.Context, zone, group, name, recordType string, rrset RRSet) (*APIRRSet, error) {
	path := fmt.Sprintf(rrsetPathPattern+"/%s/%s", zone, group, name, recordType)
	body := APIRRSet{
		DNSZoneName: zone,
		GroupName:   group,
		RecordName:  name,
		Type:        recordType,
		RRSet:       rrset,
	}
	var result APIRRSet
	if err := c.doWithRetry(ctx, http.MethodPut, path, body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DeleteRRSet removes a DNS record set.
func (c *Client) DeleteRRSet(ctx context.Context, zone, group, name, recordType string) error {
	path := fmt.Sprintf(rrsetPathPattern+"/%s/%s", zone, group, name, recordType)
	return c.do(ctx, http.MethodDelete, path, nil, nil)
}

// do performs an HTTP request with JSON marshalling, authentication, and response parsing.
func (c *Client) do(ctx context.Context, method, path string, payload, result interface{}) error {
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("f5xc: failed to marshal request body: %w", err)
		}
		body = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return fmt.Errorf("f5xc: failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	if err := c.auth.Apply(req); err != nil {
		return fmt.Errorf("f5xc: authentication failed: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("f5xc: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("f5xc: failed to read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiErr APIError
		if err := json.Unmarshal(respBody, &apiErr); err != nil {
			return fmt.Errorf("f5xc: HTTP %d: %s", resp.StatusCode, string(respBody))
		}
		apiErr.StatusCode = resp.StatusCode
		return &apiErr
	}

	if result != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("f5xc: failed to unmarshal response: %w", err)
		}
	}

	return nil
}

// doWithRetry wraps do with retry logic for transient 503 errors.
// It retries with a constant backoff until retryMaxElapsed is exceeded or the context is cancelled.
func (c *Client) doWithRetry(ctx context.Context, method, path string, payload, result interface{}) error {
	deadline := time.Now().Add(retryMaxElapsed)

	for {
		err := c.do(ctx, method, path, payload, result)
		if err == nil {
			return nil
		}

		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusServiceUnavailable || apiErr.Code != retryableCode {
			return err
		}

		// Check if we've exceeded the max elapsed time.
		if time.Now().Add(retryInterval).After(deadline) {
			return err
		}

		// Wait for the retry interval or context cancellation.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(retryInterval):
			// Continue to next attempt.
		}
	}
}
