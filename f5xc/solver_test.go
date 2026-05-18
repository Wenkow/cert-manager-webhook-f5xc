package f5xc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	acme "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/wenkow/cert-manager-webhook-f5xc/f5xc/client"
)

type mockClient struct {
	getRRSet     func(ctx context.Context, zone, group, name, recordType string) (*client.APIRRSet, error)
	createRRSet  func(ctx context.Context, zone, group string, rrset client.RRSet) (*client.APIRRSet, error)
	replaceRRSet func(ctx context.Context, zone, group, name, recordType string, rrset client.RRSet) (*client.APIRRSet, error)
	deleteRRSet  func(ctx context.Context, zone, group, name, recordType string) error
}

func (m *mockClient) GetRRSet(ctx context.Context, zone, group, name, recordType string) (*client.APIRRSet, error) {
	return m.getRRSet(ctx, zone, group, name, recordType)
}
func (m *mockClient) CreateRRSet(ctx context.Context, zone, group string, rrset client.RRSet) (*client.APIRRSet, error) {
	return m.createRRSet(ctx, zone, group, rrset)
}
func (m *mockClient) ReplaceRRSet(ctx context.Context, zone, group, name, recordType string, rrset client.RRSet) (*client.APIRRSet, error) {
	return m.replaceRRSet(ctx, zone, group, name, recordType, rrset)
}
func (m *mockClient) DeleteRRSet(ctx context.Context, zone, group, name, recordType string) error {
	return m.deleteRRSet(ctx, zone, group, name, recordType)
}

func challengeRequest(fqdn, zone, key string, config map[string]any) *acme.ChallengeRequest {
	raw, _ := json.Marshal(config)
	return &acme.ChallengeRequest{
		ResolvedFQDN:      fqdn,
		ResolvedZone:      zone,
		Key:               key,
		ResourceNamespace: "default",
		Config:            &extapi.JSON{Raw: raw},
	}
}

type fakeSecretReader struct {
	data map[string][]byte
}

func (f *fakeSecretReader) GetSecretData(namespace, name string) (map[string][]byte, error) {
	return f.data, nil
}

func TestSolver_Name(t *testing.T) {
	s := &Solver{}
	if s.Name() != "f5xc" {
		t.Errorf("Name() = %s, want f5xc", s.Name())
	}
}

func TestSolver_Present_NewRecord(t *testing.T) {
	var createdRRSet client.RRSet
	mc := &mockClient{
		getRRSet: func(ctx context.Context, zone, group, name, recordType string) (*client.APIRRSet, error) {
			return nil, nil
		},
		createRRSet: func(ctx context.Context, zone, group string, rrset client.RRSet) (*client.APIRRSet, error) {
			createdRRSet = rrset
			return &client.APIRRSet{}, nil
		},
	}
	s := &Solver{
		clientFactory: func(cfg *F5XCConfig, auth client.Authenticator) (RRSetClient, error) { return mc, nil },
		secretReader:  &fakeSecretReader{data: map[string][]byte{"api-token": []byte("test-token")}},
	}
	ch := challengeRequest("_acme-challenge.example.com.", "example.com.", "challenge-key", map[string]any{
		"tenantName": "my-tenant", "groupName": "cert-manager",
		"apiTokenSecretRef": map[string]string{"name": "secret", "key": "api-token"},
	})
	if err := s.Present(ch); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if createdRRSet.TXTRecord == nil {
		t.Fatal("expected TXT record to be created")
	}
	if createdRRSet.TXTRecord.Name != "_acme-challenge" {
		t.Errorf("name = %s, want _acme-challenge", createdRRSet.TXTRecord.Name)
	}
	if len(createdRRSet.TXTRecord.Values) != 1 || createdRRSet.TXTRecord.Values[0] != "challenge-key" {
		t.Errorf("values = %v, want [challenge-key]", createdRRSet.TXTRecord.Values)
	}
	if createdRRSet.TTL != 120 {
		t.Errorf("TTL = %d, want 120", createdRRSet.TTL)
	}
}

func TestSolver_Present_AppendToExisting(t *testing.T) {
	var replacedRRSet client.RRSet
	mc := &mockClient{
		getRRSet: func(ctx context.Context, zone, group, name, recordType string) (*client.APIRRSet, error) {
			return &client.APIRRSet{
				RRSet: client.RRSet{TXTRecord: &client.TXTRecord{Name: "_acme-challenge", Values: []string{"existing-value"}}},
			}, nil
		},
		replaceRRSet: func(ctx context.Context, zone, group, name, recordType string, rrset client.RRSet) (*client.APIRRSet, error) {
			replacedRRSet = rrset
			return &client.APIRRSet{}, nil
		},
	}
	s := &Solver{
		clientFactory: func(cfg *F5XCConfig, auth client.Authenticator) (RRSetClient, error) { return mc, nil },
		secretReader:  &fakeSecretReader{data: map[string][]byte{"api-token": []byte("test-token")}},
	}
	ch := challengeRequest("_acme-challenge.example.com.", "example.com.", "new-value", map[string]any{
		"tenantName": "my-tenant", "groupName": "cert-manager",
		"apiTokenSecretRef": map[string]string{"name": "secret", "key": "api-token"},
	})
	if err := s.Present(ch); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(replacedRRSet.TXTRecord.Values) != 2 {
		t.Fatalf("values count = %d, want 2", len(replacedRRSet.TXTRecord.Values))
	}
	if replacedRRSet.TXTRecord.Values[0] != "existing-value" || replacedRRSet.TXTRecord.Values[1] != "new-value" {
		t.Errorf("values = %v, want [existing-value new-value]", replacedRRSet.TXTRecord.Values)
	}
}

func TestSolver_CleanUp(t *testing.T) {
	deleted := false
	mc := &mockClient{
		deleteRRSet: func(ctx context.Context, zone, group, name, recordType string) error {
			deleted = true
			if zone != "example.com" {
				t.Errorf("zone = %s, want example.com", zone)
			}
			if name != "_acme-challenge" {
				t.Errorf("name = %s, want _acme-challenge", name)
			}
			return nil
		},
	}
	s := &Solver{
		clientFactory: func(cfg *F5XCConfig, auth client.Authenticator) (RRSetClient, error) { return mc, nil },
		secretReader:  &fakeSecretReader{data: map[string][]byte{"api-token": []byte("test-token")}},
	}
	ch := challengeRequest("_acme-challenge.example.com.", "example.com.", "challenge-key", map[string]any{
		"tenantName": "my-tenant", "groupName": "cert-manager",
		"apiTokenSecretRef": map[string]string{"name": "secret", "key": "api-token"},
	})
	if err := s.CleanUp(ch); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !deleted {
		t.Error("expected DeleteRRSet to be called")
	}
}

func generateTestP12Bytes(t *testing.T) []byte {
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
	p12Data, err := pkcs12.Modern.Encode(key, cert, nil, "test-password")
	if err != nil {
		t.Fatal(err)
	}
	return p12Data
}

func TestSolver_Present_CertAuth(t *testing.T) {
	var createdRRSet client.RRSet
	mc := &mockClient{
		getRRSet: func(ctx context.Context, zone, group, name, recordType string) (*client.APIRRSet, error) {
			return nil, nil
		},
		createRRSet: func(ctx context.Context, zone, group string, rrset client.RRSet) (*client.APIRRSet, error) {
			createdRRSet = rrset
			return &client.APIRRSet{}, nil
		},
	}

	s := &Solver{
		clientFactory: func(cfg *F5XCConfig, auth client.Authenticator) (RRSetClient, error) {
			if _, ok := auth.(*client.TokenAuth); ok {
				t.Error("expected CertAuth, got TokenAuth")
			}
			return mc, nil
		},
		secretReader: &fakeSecretReader{data: map[string][]byte{
			"cert.p12": generateTestP12Bytes(t),
			"password": []byte("test-password"),
		}},
	}

	ch := challengeRequest("_acme-challenge.example.com.", "example.com.", "challenge-key", map[string]any{
		"tenantName": "my-tenant", "groupName": "cert-manager",
		"certificateSecretRef": map[string]string{"name": "secret", "p12Key": "cert.p12", "passwordKey": "password"},
	})

	if err := s.Present(ch); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if createdRRSet.TXTRecord == nil {
		t.Fatal("expected TXT record to be created")
	}
}
