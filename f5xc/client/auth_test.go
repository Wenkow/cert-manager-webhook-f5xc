package client

import (
	"net/http"
	"testing"
)

func TestTokenAuth_Apply(t *testing.T) {
	auth := &TokenAuth{Token: "test-token-123"}
	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := auth.Apply(req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := req.Header.Get("Authorization")
	want := "APIToken test-token-123"
	if got != want {
		t.Errorf("Authorization header = %q, want %q", got, want)
	}
}

func TestTokenAuth_EmptyToken(t *testing.T) {
	auth := &TokenAuth{Token: ""}
	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	err = auth.Apply(req)
	if err == nil {
		t.Fatal("expected error for empty token, got nil")
	}
}
