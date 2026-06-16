package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
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

func generateTestP12(t *testing.T) ([]byte, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	password := "test-password"
	p12Data, err := pkcs12.Modern.Encode(key, cert, nil, password)
	if err != nil {
		t.Fatal(err)
	}
	return p12Data, password
}

func TestCertAuth_Transport(t *testing.T) {
	p12Data, password := generateTestP12(t)
	auth, err := NewCertAuth(p12Data, password)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	transport := auth.Transport()
	if transport == nil {
		t.Fatal("expected non-nil transport")
	}
	if transport.TLSClientConfig == nil {
		t.Fatal("expected non-nil TLS config")
	}
	if len(transport.TLSClientConfig.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(transport.TLSClientConfig.Certificates))
	}
}

func TestCertAuth_RootCAsNil(t *testing.T) {
	p12Data, password := generateTestP12(t)
	auth, err := NewCertAuth(p12Data, password)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// RootCAs must stay nil so the server cert is verified against the system trust
	// store; it must not be replaced by the client chain from the P12.
	if auth.Transport().TLSClientConfig.RootCAs != nil {
		t.Error("RootCAs should be nil (system trust store), got non-nil")
	}
}

func TestCertAuth_Apply(t *testing.T) {
	p12Data, password := generateTestP12(t)
	auth, err := NewCertAuth(p12Data, password)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.Apply(req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Header.Get("Authorization") != "" {
		t.Error("CertAuth should not set Authorization header")
	}
}

func TestCertAuth_EmptyP12(t *testing.T) {
	_, err := NewCertAuth(nil, "password")
	if err == nil {
		t.Fatal("expected error for nil P12 data")
	}
}

func TestCertAuth_WrongPassword(t *testing.T) {
	p12Data, _ := generateTestP12(t)
	_, err := NewCertAuth(p12Data, "wrong-password")
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}
