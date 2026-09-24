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
	"sync"
	"testing"
	"time"

	acme "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/wenkow/cert-manager-webhook-f5xc/f5xc/client"
)

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
	fastReconcile(t)
	fc := newFakeRRSetClient()
	ch := f5xcChallenge("challenge-key")
	if err := fakeSolver(fc).Present(ch); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := fc.values("_acme-challenge"); len(got) != 1 || got[0] != "challenge-key" {
		t.Fatalf("values = %v, want [challenge-key]", got)
	}
	if fc.creates != 1 {
		t.Errorf("creates = %d, want 1", fc.creates)
	}
}

func TestSolver_Present_AppendToExisting(t *testing.T) {
	fastReconcile(t)
	fc := newFakeRRSetClient()
	fc.records["_acme-challenge"] = client.RRSet{TXTRecord: &client.TXTRecord{Name: "_acme-challenge", Values: []string{"existing-value"}}}
	if err := fakeSolver(fc).Present(f5xcChallenge("new-value")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := fc.values("_acme-challenge")
	if len(got) != 2 || got[0] != "existing-value" || got[1] != "new-value" {
		t.Fatalf("values = %v, want [existing-value new-value]", got)
	}
}

func TestSolver_Present_DuplicateValue(t *testing.T) {
	fastReconcile(t)
	fc := newFakeRRSetClient()
	fc.records["_acme-challenge"] = client.RRSet{TXTRecord: &client.TXTRecord{Name: "_acme-challenge", Values: []string{"challenge-key"}}}
	if err := fakeSolver(fc).Present(f5xcChallenge("challenge-key")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fc.creates != 0 || fc.replaces != 0 {
		t.Errorf("no write expected for duplicate; creates=%d replaces=%d", fc.creates, fc.replaces)
	}
	if got := fc.values("_acme-challenge"); len(got) != 1 {
		t.Fatalf("values = %v, want exactly [challenge-key]", got)
	}
}

// First write is silently lost; the read-back must detect the value is missing and
// re-apply, converging without error.
func TestSolver_Present_ReadBackRecoversLostWrite(t *testing.T) {
	fastReconcile(t)
	fc := newFakeRRSetClient()
	fc.loseWrites = 1 // drop the first create
	if err := fakeSolver(fc).Present(f5xcChallenge("challenge-key")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := fc.values("_acme-challenge"); len(got) != 1 || got[0] != "challenge-key" {
		t.Fatalf("value did not converge; values = %v", got)
	}
	if fc.creates < 2 {
		t.Errorf("expected at least 2 create attempts (one lost), got %d", fc.creates)
	}
}

// Every write is lost; Present must error after verifyAttempts rather than hang.
func TestSolver_Present_ErrorsWhenNeverConverges(t *testing.T) {
	fastReconcile(t)
	fc := newFakeRRSetClient()
	fc.loseWrites = 1000 // drop them all
	err := fakeSolver(fc).Present(f5xcChallenge("challenge-key"))
	if err == nil {
		t.Fatal("expected error when value never converges")
	}
	if fc.creates != verifyAttempts {
		t.Errorf("create attempts = %d, want %d", fc.creates, verifyAttempts)
	}
}

// f5xcChallenge builds a standard token-auth challenge request for the test tenant.
func f5xcChallenge(key string) *acme.ChallengeRequest {
	return challengeRequest("_acme-challenge.example.com.", "example.com.", key, map[string]any{
		"tenantName": "my-tenant", "groupName": "cert-manager",
		"apiTokenSecretRef": map[string]string{"name": "secret", "key": "api-token"},
	})
}

// TestSolver_Present_DuplicateValue covers Bug 1: Present must be idempotent and
// must not append a value that is already in the RRSet (F5 XC rejects duplicates).

func TestSolver_CleanUp_RemovesOnlyOwnValue(t *testing.T) {
	fastReconcile(t)
	fc := newFakeRRSetClient()
	fc.records["_acme-challenge"] = client.RRSet{TXTRecord: &client.TXTRecord{Name: "_acme-challenge", Values: []string{"other-key", "challenge-key"}}}
	if err := fakeSolver(fc).CleanUp(f5xcChallenge("challenge-key")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := fc.values("_acme-challenge")
	if len(got) != 1 || got[0] != "other-key" {
		t.Fatalf("values = %v, want [other-key]", got)
	}
	if fc.deletes != 0 {
		t.Errorf("deletes = %d, want 0 (other value remains)", fc.deletes)
	}
}

func TestSolver_CleanUp_ThreeChallenges_RemovesOnlyVerified(t *testing.T) {
	fastReconcile(t)
	fc := newFakeRRSetClient()
	fc.records["_acme-challenge"] = client.RRSet{TXTRecord: &client.TXTRecord{Name: "_acme-challenge", Values: []string{"key-1", "key-verified", "key-3"}}}
	if err := fakeSolver(fc).CleanUp(f5xcChallenge("key-verified")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := fc.values("_acme-challenge")
	remaining := map[string]bool{}
	for _, v := range got {
		remaining[v] = true
	}
	if len(got) != 2 || !remaining["key-1"] || !remaining["key-3"] {
		t.Errorf("values = %v, want [key-1 key-3]", got)
	}
	if fc.deletes != 0 {
		t.Errorf("deletes = %d, want 0", fc.deletes)
	}
}

func TestSolver_CleanUp_DeletesWhenLast(t *testing.T) {
	fastReconcile(t)
	fc := newFakeRRSetClient()
	fc.records["_acme-challenge"] = client.RRSet{TXTRecord: &client.TXTRecord{Name: "_acme-challenge", Values: []string{"challenge-key"}}}
	if err := fakeSolver(fc).CleanUp(f5xcChallenge("challenge-key")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := fc.values("_acme-challenge"); got != nil {
		t.Fatalf("expected record deleted, values = %v", got)
	}
	if fc.deletes != 1 {
		t.Errorf("deletes = %d, want 1", fc.deletes)
	}
}

func TestSolver_CleanUp_AlreadyGone(t *testing.T) {
	fastReconcile(t)
	fc := newFakeRRSetClient() // empty
	if err := fakeSolver(fc).CleanUp(f5xcChallenge("challenge-key")); err != nil {
		t.Fatalf("expected nil error when record absent, got: %v", err)
	}
	if fc.deletes != 0 || fc.replaces != 0 {
		t.Errorf("no write expected; deletes=%d replaces=%d", fc.deletes, fc.replaces)
	}
}

// A delete that reports "not found" means the record is already gone, so the
// reconcile loop must tolerate the error rather than fail the challenge.
func TestSolver_CleanUp_DeleteNotFoundTolerated(t *testing.T) {
	fastReconcile(t)
	fc := newFakeRRSetClient()
	fc.records["_acme-challenge"] = client.RRSet{TXTRecord: &client.TXTRecord{Name: "_acme-challenge", Values: []string{"challenge-key"}}}
	fc.deleteErr = &client.APIError{Code: 5, Message: "not found"}
	if err := fakeSolver(fc).CleanUp(f5xcChallenge("challenge-key")); err != nil {
		t.Fatalf("expected nil error on not-found delete, got: %v", err)
	}
	if got := fc.values("_acme-challenge"); got != nil {
		t.Fatalf("expected record gone, values = %v", got)
	}
}

// First delete is silently lost; the read-back must re-issue it and converge.
func TestSolver_CleanUp_ReadBackRecoversLostDelete(t *testing.T) {
	fastReconcile(t)
	fc := newFakeRRSetClient()
	fc.records["_acme-challenge"] = client.RRSet{TXTRecord: &client.TXTRecord{Name: "_acme-challenge", Values: []string{"challenge-key"}}}
	fc.loseWrites = 1 // drop the first delete
	if err := fakeSolver(fc).CleanUp(f5xcChallenge("challenge-key")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := fc.values("_acme-challenge"); got != nil {
		t.Fatalf("delete did not converge; values = %v", got)
	}
	if fc.deletes < 2 {
		t.Errorf("expected at least 2 delete attempts (one lost), got %d", fc.deletes)
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
	fastReconcile(t)
	fc := newFakeRRSetClient()
	s := &Solver{
		clientFactory: func(cfg *F5XCConfig, auth client.Authenticator) (RRSetClient, error) {
			if _, ok := auth.(*client.TokenAuth); ok {
				t.Error("expected CertAuth, got TokenAuth")
			}
			return fc, nil
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
	if got := fc.values("_acme-challenge"); len(got) != 1 || got[0] != "challenge-key" {
		t.Fatalf("values = %v, want [challenge-key]", got)
	}
}

// fakeRRSetClient is an in-memory RRSetClient whose GET reflects prior writes,
// so it can model F5 XC's read-modify-write semantics for the reconcile loop.
// It is safe for concurrent use. Records are keyed by record name (tests use a
// single zone/group, all TXT).
type fakeRRSetClient struct {
	mu       sync.Mutex
	records  map[string]client.RRSet // name -> rrset
	creates  int
	replaces int
	deletes  int
	gets     int
	// loseWrites silently drops this many upcoming Create/Replace/Delete calls
	// (they return success but do not change state) to simulate a lost/lagging write.
	loseWrites int
	// deleteErr, when set, is returned by DeleteRRSet after the delete is applied,
	// so tests can exercise how the caller treats a delete that reports not-found.
	deleteErr error
}

func newFakeRRSetClient() *fakeRRSetClient {
	return &fakeRRSetClient{records: map[string]client.RRSet{}}
}

func (f *fakeRRSetClient) GetRRSet(_ context.Context, _, _, name, _ string) (*client.APIRRSet, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets++
	rr, ok := f.records[name]
	if !ok {
		return nil, nil // not found, mirrors client.GetRRSet
	}
	// return a deep copy so callers cannot mutate our state
	vals := append([]string{}, rr.TXTRecord.Values...)
	return &client.APIRRSet{RRSet: client.RRSet{
		TTL:       rr.TTL,
		TXTRecord: &client.TXTRecord{Name: rr.TXTRecord.Name, Values: vals},
	}}, nil
}

func (f *fakeRRSetClient) CreateRRSet(_ context.Context, _, _ string, rrset client.RRSet) (*client.APIRRSet, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.creates++
	if f.loseWrites > 0 {
		f.loseWrites--
		return &client.APIRRSet{}, nil
	}
	f.records[rrset.TXTRecord.Name] = rrset
	return &client.APIRRSet{}, nil
}

func (f *fakeRRSetClient) ReplaceRRSet(_ context.Context, _, _, name, _ string, rrset client.RRSet) (*client.APIRRSet, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.replaces++
	if f.loseWrites > 0 {
		f.loseWrites--
		return &client.APIRRSet{}, nil
	}
	f.records[name] = rrset
	return &client.APIRRSet{}, nil
}

func (f *fakeRRSetClient) DeleteRRSet(_ context.Context, _, _, name, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletes++
	if f.loseWrites > 0 {
		f.loseWrites--
		return nil
	}
	delete(f.records, name)
	return f.deleteErr
}

// values returns the stored TXT values for a record name (nil if absent).
func (f *fakeRRSetClient) values(name string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	rr, ok := f.records[name]
	if !ok {
		return nil
	}
	return append([]string{}, rr.TXTRecord.Values...)
}

// fakeSolver builds a Solver backed by the given fake client and a token-auth secret.
func fakeSolver(fc *fakeRRSetClient) *Solver {
	return &Solver{
		clientFactory: func(cfg *F5XCConfig, auth client.Authenticator) (RRSetClient, error) { return fc, nil },
		secretReader:  &fakeSecretReader{data: map[string][]byte{"api-token": []byte("test-token")}},
	}
}

// fastReconcile makes the reconcile loop run without real backoff for the duration
// of a test. Tests using it must NOT call t.Parallel() (it mutates package vars).
func fastReconcile(t *testing.T) {
	t.Helper()
	oldInterval, oldAttempts := verifyInterval, verifyAttempts
	verifyInterval = 0
	verifyAttempts = 3
	t.Cleanup(func() { verifyInterval, verifyAttempts = oldInterval, oldAttempts })
}

func TestFakeRRSetClient_Sanity(t *testing.T) {
	fc := newFakeRRSetClient()
	ctx := context.Background()
	if rr, _ := fc.GetRRSet(ctx, "z", "g", "n", "TXT"); rr != nil {
		t.Fatal("expected nil for absent record")
	}
	_, _ = fc.CreateRRSet(ctx, "z", "g", client.RRSet{TXTRecord: &client.TXTRecord{Name: "n", Values: []string{"a"}}})
	if got := fc.values("n"); len(got) != 1 || got[0] != "a" {
		t.Fatalf("after create, values = %v, want [a]", got)
	}
	_, _ = fc.ReplaceRRSet(ctx, "z", "g", "n", "TXT", client.RRSet{TXTRecord: &client.TXTRecord{Name: "n", Values: []string{"a", "b"}}})
	if got := fc.values("n"); len(got) != 2 {
		t.Fatalf("after replace, values = %v, want 2", got)
	}
	_ = fc.DeleteRRSet(ctx, "z", "g", "n", "TXT")
	if got := fc.values("n"); got != nil {
		t.Fatalf("after delete, values = %v, want nil", got)
	}
}
