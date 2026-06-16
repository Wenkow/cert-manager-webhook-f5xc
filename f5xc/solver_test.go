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

// f5xcChallenge builds a standard token-auth challenge request for the test tenant.
func f5xcChallenge(key string) *acme.ChallengeRequest {
	return challengeRequest("_acme-challenge.example.com.", "example.com.", key, map[string]any{
		"tenantName": "my-tenant", "groupName": "cert-manager",
		"apiTokenSecretRef": map[string]string{"name": "secret", "key": "api-token"},
	})
}

func tokenSolver(mc *mockClient) *Solver {
	return &Solver{
		clientFactory: func(cfg *F5XCConfig, auth client.Authenticator) (RRSetClient, error) { return mc, nil },
		secretReader:  &fakeSecretReader{data: map[string][]byte{"api-token": []byte("test-token")}},
	}
}

// TestSolver_Present_DuplicateValue covers Bug 1: Present must be idempotent and
// must not append a value that is already in the RRSet (F5 XC rejects duplicates).
func TestSolver_Present_DuplicateValue(t *testing.T) {
	replaceCalled := false
	createCalled := false
	mc := &mockClient{
		getRRSet: func(ctx context.Context, zone, group, name, recordType string) (*client.APIRRSet, error) {
			return &client.APIRRSet{
				RRSet: client.RRSet{TXTRecord: &client.TXTRecord{Name: "_acme-challenge", Values: []string{"challenge-key"}}},
			}, nil
		},
		replaceRRSet: func(ctx context.Context, zone, group, name, recordType string, rrset client.RRSet) (*client.APIRRSet, error) {
			replaceCalled = true
			return &client.APIRRSet{}, nil
		},
		createRRSet: func(ctx context.Context, zone, group string, rrset client.RRSet) (*client.APIRRSet, error) {
			createCalled = true
			return &client.APIRRSet{}, nil
		},
	}
	if err := tokenSolver(mc).Present(f5xcChallenge("challenge-key")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if replaceCalled {
		t.Error("ReplaceRRSet should not be called when value already present")
	}
	if createCalled {
		t.Error("CreateRRSet should not be called when value already present")
	}
}

// TestSolver_CleanUp_RemovesOnlyOwnValue covers Bug 2: when other challenges share
// the RRSet, cleanup must REPLACE with the remaining values, not delete everything.
func TestSolver_CleanUp_RemovesOnlyOwnValue(t *testing.T) {
	var replaced client.RRSet
	deleteCalled := false
	mc := &mockClient{
		getRRSet: func(ctx context.Context, zone, group, name, recordType string) (*client.APIRRSet, error) {
			return &client.APIRRSet{
				RRSet: client.RRSet{TXTRecord: &client.TXTRecord{Name: "_acme-challenge", Values: []string{"other-key", "challenge-key"}}},
			}, nil
		},
		replaceRRSet: func(ctx context.Context, zone, group, name, recordType string, rrset client.RRSet) (*client.APIRRSet, error) {
			replaced = rrset
			return &client.APIRRSet{}, nil
		},
		deleteRRSet: func(ctx context.Context, zone, group, name, recordType string) error {
			deleteCalled = true
			return nil
		},
	}
	if err := tokenSolver(mc).CleanUp(f5xcChallenge("challenge-key")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deleteCalled {
		t.Error("DeleteRRSet must not be called when other values remain")
	}
	if replaced.TXTRecord == nil || len(replaced.TXTRecord.Values) != 1 || replaced.TXTRecord.Values[0] != "other-key" {
		t.Errorf("replaced values = %v, want [other-key]", replaced.TXTRecord)
	}
}

// TestSolver_CleanUp_DeletesWhenLast covers Bug 2: when our value is the only one
// left, the whole RRSet is deleted.
func TestSolver_CleanUp_DeletesWhenLast(t *testing.T) {
	deleteCalled := false
	mc := &mockClient{
		getRRSet: func(ctx context.Context, zone, group, name, recordType string) (*client.APIRRSet, error) {
			return &client.APIRRSet{
				RRSet: client.RRSet{TXTRecord: &client.TXTRecord{Name: "_acme-challenge", Values: []string{"challenge-key"}}},
			}, nil
		},
		deleteRRSet: func(ctx context.Context, zone, group, name, recordType string) error {
			deleteCalled = true
			if zone != "example.com" || name != "_acme-challenge" {
				t.Errorf("delete args zone=%s name=%s", zone, name)
			}
			return nil
		},
	}
	if err := tokenSolver(mc).CleanUp(f5xcChallenge("challenge-key")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !deleteCalled {
		t.Error("expected DeleteRRSet to be called for the last value")
	}
}

// TestSolver_CleanUp_AlreadyGone covers Bug 3: a missing RRSet (GET returns nil) is
// not an error — cleanup is idempotent.
func TestSolver_CleanUp_AlreadyGone(t *testing.T) {
	mc := &mockClient{
		getRRSet: func(ctx context.Context, zone, group, name, recordType string) (*client.APIRRSet, error) {
			return nil, nil
		},
	}
	if err := tokenSolver(mc).CleanUp(f5xcChallenge("challenge-key")); err != nil {
		t.Fatalf("expected nil error when RRSet already gone, got: %v", err)
	}
}

// TestSolver_CleanUp_DeleteNotFound covers Bug 3: an API code-5 (NOT_FOUND) error on
// the final delete is swallowed.
func TestSolver_CleanUp_DeleteNotFound(t *testing.T) {
	mc := &mockClient{
		getRRSet: func(ctx context.Context, zone, group, name, recordType string) (*client.APIRRSet, error) {
			return &client.APIRRSet{
				RRSet: client.RRSet{TXTRecord: &client.TXTRecord{Name: "_acme-challenge", Values: []string{"challenge-key"}}},
			}, nil
		},
		deleteRRSet: func(ctx context.Context, zone, group, name, recordType string) error {
			return &client.APIError{Code: 5, Message: "not found"}
		},
	}
	if err := tokenSolver(mc).CleanUp(f5xcChallenge("challenge-key")); err != nil {
		t.Fatalf("expected nil error on not-found delete, got: %v", err)
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
