package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type mockAuth struct{}

func (m *mockAuth) Apply(req *http.Request) error {
	req.Header.Set("Authorization", "APIToken mock-token")
	return nil
}

func TestNewClient(t *testing.T) {
	_, err := NewClient("test-tenant", "console.ves.volterra.io", &mockAuth{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewClient_EmptyTenant(t *testing.T) {
	_, err := NewClient("", "console.ves.volterra.io", &mockAuth{})
	if err == nil {
		t.Fatal("expected error for empty tenant, got nil")
	}
}

func TestNewClient_BaseURL(t *testing.T) {
	c, err := NewClient("acme", "console.ves.volterra.io", &mockAuth{})
	if err != nil {
		t.Fatal(err)
	}
	want := "https://acme.console.ves.volterra.io"
	if c.baseURL != want {
		t.Errorf("baseURL = %q, want %q", c.baseURL, want)
	}
}

func TestNewClient_DefaultServer(t *testing.T) {
	c, err := NewClient("acme", "", &mockAuth{})
	if err != nil {
		t.Fatal(err)
	}
	want := "https://acme.console.ves.volterra.io"
	if c.baseURL != want {
		t.Errorf("baseURL = %q, want %q", c.baseURL, want)
	}
}

func TestClient_AuthHeaderSent(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(APIError{Code: 5, Message: "not found"})
	}))
	defer srv.Close()

	c := &Client{
		baseURL:    srv.URL,
		auth:       &mockAuth{},
		httpClient: srv.Client(),
	}

	c.GetRRSet(context.Background(), "example.com", "grp", "sub", "TXT")

	if gotAuth != "APIToken mock-token" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "APIToken mock-token")
	}
}

func newTestServer(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return &Client{
		baseURL:    srv.URL,
		auth:       &mockAuth{},
		httpClient: srv.Client(),
	}
}

func TestClient_CreateRRSet(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody APIRRSet

	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(APIRRSet{
			DNSZoneName: "example.com",
			GroupName:   "grp",
			RecordName:  "_acme-challenge",
		})
	})

	input := APIRRSet{
		RRSet: RRSet{
			TTL: 60,
			TXTRecord: &TXTRecord{
				Name:   "_acme-challenge",
				Values: []string{"token123"},
			},
		},
	}

	result, err := c.CreateRRSet(context.Background(), "example.com", "grp", input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	wantPath := "/api/config/dns/namespaces/system/dns_zones/example.com/rrsets/grp"
	if gotPath != wantPath {
		t.Errorf("path = %q, want %q", gotPath, wantPath)
	}
	if gotBody.RRSet.TXTRecord == nil || gotBody.RRSet.TXTRecord.Name != "_acme-challenge" {
		t.Errorf("request body not parsed correctly: %+v", gotBody)
	}
	if result.DNSZoneName != "example.com" {
		t.Errorf("response DNSZoneName = %q, want %q", result.DNSZoneName, "example.com")
	}
}

func TestClient_GetRRSet(t *testing.T) {
	var gotMethod, gotPath string

	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(APIRRSet{
			DNSZoneName: "example.com",
			GroupName:   "grp",
			RecordName:  "_acme-challenge",
			Type:        "TXT",
		})
	})

	result, err := c.GetRRSet(context.Background(), "example.com", "grp", "_acme-challenge", "TXT")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotMethod != http.MethodGet {
		t.Errorf("method = %q, want GET", gotMethod)
	}
	wantPath := "/api/config/dns/namespaces/system/dns_zones/example.com/rrsets/grp/_acme-challenge/TXT"
	if gotPath != wantPath {
		t.Errorf("path = %q, want %q", gotPath, wantPath)
	}
	if result.RecordName != "_acme-challenge" {
		t.Errorf("RecordName = %q, want %q", result.RecordName, "_acme-challenge")
	}
}

func TestClient_GetRRSet_NotFound(t *testing.T) {
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(APIError{Code: 5, Message: "not found"})
	})

	result, err := c.GetRRSet(context.Background(), "example.com", "grp", "nonexistent", "TXT")
	if err != nil {
		t.Fatalf("expected nil error for 404, got: %v", err)
	}
	if result != nil {
		t.Fatalf("expected nil result for 404, got: %+v", result)
	}
}

func TestClient_ReplaceRRSet(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody APIRRSet

	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(APIRRSet{
			DNSZoneName: "example.com",
			RecordName:  "_acme-challenge",
			Type:        "TXT",
		})
	})

	input := APIRRSet{
		RRSet: RRSet{
			TTL: 120,
			TXTRecord: &TXTRecord{
				Name:   "_acme-challenge",
				Values: []string{"new-token"},
			},
		},
	}

	result, err := c.ReplaceRRSet(context.Background(), "example.com", "grp", "_acme-challenge", "TXT", input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotMethod != http.MethodPut {
		t.Errorf("method = %q, want PUT", gotMethod)
	}
	wantPath := "/api/config/dns/namespaces/system/dns_zones/example.com/rrsets/grp/_acme-challenge/TXT"
	if gotPath != wantPath {
		t.Errorf("path = %q, want %q", gotPath, wantPath)
	}
	if gotBody.Type != "TXT" {
		t.Errorf("request body Type = %q, want %q", gotBody.Type, "TXT")
	}
	if result.RecordName != "_acme-challenge" {
		t.Errorf("RecordName = %q, want %q", result.RecordName, "_acme-challenge")
	}
}

func TestClient_DeleteRRSet(t *testing.T) {
	var gotMethod, gotPath string

	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	})

	err := c.DeleteRRSet(context.Background(), "example.com", "grp", "_acme-challenge", "TXT")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotMethod != http.MethodDelete {
		t.Errorf("method = %q, want DELETE", gotMethod)
	}
	wantPath := "/api/config/dns/namespaces/system/dns_zones/example.com/rrsets/grp/_acme-challenge/TXT"
	if gotPath != wantPath {
		t.Errorf("path = %q, want %q", gotPath, wantPath)
	}
}

func TestClient_APIError(t *testing.T) {
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(APIError{Code: 7, Message: "permission denied"})
	})

	_, err := c.GetRRSet(context.Background(), "example.com", "grp", "sub", "TXT")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusForbidden {
		t.Errorf("StatusCode = %d, want %d", apiErr.StatusCode, http.StatusForbidden)
	}
	if apiErr.Code != 7 {
		t.Errorf("Code = %d, want %d", apiErr.Code, 7)
	}
	if apiErr.Message != "permission denied" {
		t.Errorf("Message = %q, want %q", apiErr.Message, "permission denied")
	}
}
