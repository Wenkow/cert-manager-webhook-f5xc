package client

import (
	"context"
	"encoding/json"
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
