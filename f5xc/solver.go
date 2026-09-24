package f5xc

import (
	"context"
	"fmt"
	"strings"
	"time"

	acme "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"github.com/wenkow/cert-manager-webhook-f5xc/f5xc/client"
)

// Reconcile/verification tuning. Vars (not consts) so tests can override them.
// Sized from live measurement (2026-09-24): the observed zone settle time was a
// median of 1.32s and a maximum of 3.22s, so a 5s read-back budget clears the
// measured worst case with margin.
var (
	verifyAttempts = 5
	verifyInterval = time.Second
)

// RRSetClient defines the DNS record operations required by the solver.
// It uses client.RRSet (the inner record struct) rather than client.APIRRSet
// to keep the solver decoupled from the API envelope.
type RRSetClient interface {
	GetRRSet(ctx context.Context, zone, group, name, recordType string) (*client.APIRRSet, error)
	CreateRRSet(ctx context.Context, zone, group string, rrset client.RRSet) (*client.APIRRSet, error)
	ReplaceRRSet(ctx context.Context, zone, group, name, recordType string, rrset client.RRSet) (*client.APIRRSet, error)
	DeleteRRSet(ctx context.Context, zone, group, name, recordType string) error
}

// SecretReader reads Kubernetes secret data.
type SecretReader interface {
	GetSecretData(namespace, name string) (map[string][]byte, error)
}

// clientFactory constructs an RRSetClient from a config and authenticator.
type clientFactory func(cfg *F5XCConfig, auth client.Authenticator) (RRSetClient, error)

// Solver implements the cert-manager webhook.Solver interface for F5 XC DNS.
type Solver struct {
	clientFactory clientFactory
	secretReader  SecretReader
	locks         keyedMutex // per-FQDN serialization; zero value is ready to use
}

// NewSolver returns a production Solver with default client factory.
func NewSolver() *Solver {
	return &Solver{
		clientFactory: defaultClientFactory,
	}
}

// Name returns the solver name used in cert-manager DNS01 config.
func (s *Solver) Name() string {
	return "f5xc"
}

// Initialize is called when the webhook apiserver starts.
// It creates a Kubernetes clientset for reading secrets.
func (s *Solver) Initialize(kubeClientConfig *restclient.Config, stopCh <-chan struct{}) error {
	clientset, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return fmt.Errorf("f5xc: creating kubernetes client: %w", err)
	}
	s.secretReader = &kubeSecretReader{clientset: clientset}
	return nil
}

// Present creates or appends a TXT record for the ACME challenge. It is idempotent
// and safe under concurrent challenges for the same FQDN.
func (s *Solver) Present(ch *acme.ChallengeRequest) error {
	cfg, cl, err := s.setup(ch)
	if err != nil {
		return err
	}

	ctx := context.Background()
	zone := unFQDN(ch.ResolvedZone)
	subdomain := extractSubDomain(ch.ResolvedFQDN, ch.ResolvedZone)

	klog.V(2).InfoS("f5xc: presenting challenge", "fqdn", ch.ResolvedFQDN, "zone", zone, "subdomain", subdomain)

	satisfied := func(values []string) bool {
		return containsValue(values, ch.Key)
	}
	mutate := func(existing *client.APIRRSet) (rrsetOp, client.RRSet) {
		if existing == nil || existing.RRSet.TXTRecord == nil {
			return opCreate, client.RRSet{
				Description: "cert-manager",
				TTL:         cfg.EffectiveTTL(),
				TXTRecord:   &client.TXTRecord{Name: subdomain, Values: []string{ch.Key}},
			}
		}
		values := append([]string{}, existing.RRSet.TXTRecord.Values...)
		values = append(values, ch.Key)
		return opReplace, client.RRSet{
			TTL:       cfg.EffectiveTTL(),
			TXTRecord: &client.TXTRecord{Name: subdomain, Values: values},
		}
	}

	return s.reconcile(ctx, cl, cfg, zone, subdomain, satisfied, mutate)
}

// CleanUp removes this challenge's value from the TXT record, preserving any other
// values (concurrent challenges for the same FQDN), deleting the record only when no
// values remain. Idempotent and safe under concurrency.
func (s *Solver) CleanUp(ch *acme.ChallengeRequest) error {
	cfg, cl, err := s.setup(ch)
	if err != nil {
		return err
	}

	ctx := context.Background()
	zone := unFQDN(ch.ResolvedZone)
	subdomain := extractSubDomain(ch.ResolvedFQDN, ch.ResolvedZone)

	klog.V(2).InfoS("f5xc: cleaning up challenge", "fqdn", ch.ResolvedFQDN, "zone", zone, "subdomain", subdomain)

	satisfied := func(values []string) bool {
		return !containsValue(values, ch.Key)
	}
	mutate := func(existing *client.APIRRSet) (rrsetOp, client.RRSet) {
		// Reached only when existing contains ch.Key (otherwise satisfied is true).
		remaining := make([]string, 0, len(existing.RRSet.TXTRecord.Values))
		for _, v := range existing.RRSet.TXTRecord.Values {
			if v != ch.Key {
				remaining = append(remaining, v)
			}
		}
		if len(remaining) == 0 {
			return opDelete, client.RRSet{}
		}
		return opReplace, client.RRSet{
			TTL:       cfg.EffectiveTTL(),
			TXTRecord: &client.TXTRecord{Name: subdomain, Values: remaining},
		}
	}

	return s.reconcile(ctx, cl, cfg, zone, subdomain, satisfied, mutate)
}

// setup is shared logic: load config, build auth, build client.
func (s *Solver) setup(ch *acme.ChallengeRequest) (*F5XCConfig, RRSetClient, error) {
	cfg, err := LoadConfig(ch.Config)
	if err != nil {
		return nil, nil, err
	}

	auth, err := s.buildAuth(cfg, ch.ResourceNamespace)
	if err != nil {
		return nil, nil, err
	}

	cl, err := s.clientFactory(cfg, auth)
	if err != nil {
		return nil, nil, fmt.Errorf("f5xc: creating API client: %w", err)
	}

	return cfg, cl, nil
}

func (s *Solver) buildAuth(cfg *F5XCConfig, namespace string) (client.Authenticator, error) {
	if cfg.APITokenSecretRef != nil {
		secretData, err := s.secretReader.GetSecretData(namespace, cfg.APITokenSecretRef.Name)
		if err != nil {
			return nil, fmt.Errorf("f5xc: reading secret %s/%s: %w", namespace, cfg.APITokenSecretRef.Name, err)
		}
		tokenBytes, ok := secretData[cfg.APITokenSecretRef.Key]
		if !ok {
			return nil, fmt.Errorf("f5xc: key %q not found in secret %s/%s", cfg.APITokenSecretRef.Key, namespace, cfg.APITokenSecretRef.Name)
		}
		return &client.TokenAuth{Token: string(tokenBytes)}, nil
	}

	ref := cfg.CertificateSecretRef
	secretData, err := s.secretReader.GetSecretData(namespace, ref.Name)
	if err != nil {
		return nil, fmt.Errorf("f5xc: reading secret %s/%s: %w", namespace, ref.Name, err)
	}
	p12Data, ok := secretData[ref.P12Key]
	if !ok {
		return nil, fmt.Errorf("f5xc: key %q not found in secret %s/%s", ref.P12Key, namespace, ref.Name)
	}
	passwordBytes, ok := secretData[ref.PasswordKey]
	if !ok {
		return nil, fmt.Errorf("f5xc: key %q not found in secret %s/%s", ref.PasswordKey, namespace, ref.Name)
	}
	return client.NewCertAuth(p12Data, string(passwordBytes))
}

// rrsetOp is the write needed to move an RRSet toward the desired state.
type rrsetOp int

const (
	opCreate rrsetOp = iota
	opReplace
	opDelete
)

// lockKey identifies a single RRSet (all records here are TXT).
func lockKey(zone, group, subdomain string) string {
	return zone + "/" + group + "/" + subdomain + "/TXT"
}

// txtValues extracts the TXT values from a GET result (nil when absent).
func txtValues(existing *client.APIRRSet) []string {
	if existing == nil || existing.RRSet.TXTRecord == nil {
		return nil
	}
	return existing.RRSet.TXTRecord.Values
}

func containsValue(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

// reconcile serializes the read-modify-write for one RRSet (per FQDN) and verifies
// the result by reading back. Each iteration: GET, return if satisfied (this is the
// read-back), otherwise apply mutate. Re-application is safe because every operation
// is idempotent. Bounded by verifyAttempts; on exhaustion it returns an error so
// cert-manager retries the challenge.
func (s *Solver) reconcile(
	ctx context.Context,
	cl RRSetClient,
	cfg *F5XCConfig,
	zone, subdomain string,
	satisfied func(values []string) bool,
	mutate func(existing *client.APIRRSet) (rrsetOp, client.RRSet),
) error {
	key := lockKey(zone, cfg.GroupName, subdomain)
	s.locks.Lock(key)
	defer s.locks.Unlock(key)

	for attempt := 1; attempt <= verifyAttempts; attempt++ {
		existing, err := cl.GetRRSet(ctx, zone, cfg.GroupName, subdomain, "TXT")
		if err != nil {
			if !client.IsNotFound(err) {
				return fmt.Errorf("f5xc: getting RRSet: %w", err)
			}
			existing = nil
		}

		if satisfied(txtValues(existing)) {
			return nil
		}

		op, rrset := mutate(existing)
		switch op {
		case opCreate:
			if _, err := cl.CreateRRSet(ctx, zone, cfg.GroupName, rrset); err != nil {
				return fmt.Errorf("f5xc: creating RRSet: %w", err)
			}
		case opReplace:
			if _, err := cl.ReplaceRRSet(ctx, zone, cfg.GroupName, subdomain, "TXT", rrset); err != nil {
				return fmt.Errorf("f5xc: replacing RRSet: %w", err)
			}
		case opDelete:
			if err := cl.DeleteRRSet(ctx, zone, cfg.GroupName, subdomain, "TXT"); err != nil && !client.IsNotFound(err) {
				return fmt.Errorf("f5xc: deleting RRSet: %w", err)
			}
		}

		if attempt < verifyAttempts {
			time.Sleep(verifyInterval)
		}
	}

	return fmt.Errorf("f5xc: RRSet %q did not converge after %d attempts", subdomain, verifyAttempts)
}

// unFQDN strips the trailing dot from a fully-qualified domain name.
func unFQDN(fqdn string) string {
	return strings.TrimSuffix(fqdn, ".")
}

// extractSubDomain extracts the subdomain part from an FQDN given a zone.
// For example, extractSubDomain("_acme-challenge.example.com.", "example.com.") returns "_acme-challenge".
func extractSubDomain(fqdn, zone string) string {
	fqdn = unFQDN(fqdn)
	zone = unFQDN(zone)
	subdomain := strings.TrimSuffix(fqdn, "."+zone)
	return subdomain
}

func defaultClientFactory(cfg *F5XCConfig, auth client.Authenticator) (RRSetClient, error) {
	return client.NewClient(cfg.TenantName, cfg.Server, auth)
}

// kubeSecretReader reads secrets from Kubernetes.
type kubeSecretReader struct {
	clientset kubernetes.Interface
}

func (r *kubeSecretReader) GetSecretData(namespace, name string) (map[string][]byte, error) {
	secret, err := r.clientset.CoreV1().Secrets(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return secret.Data, nil
}
