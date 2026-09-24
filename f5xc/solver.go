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
//
// Sized from live measurement (2026-09-24): zone settle time had a median of 1.32s
// and a maximum of 3.22s. Waiting and re-writing on a fixed 1s interval therefore
// re-wrote on almost every call, because the read-back ran before the previous write
// could propagate — and a write arriving while a change is committing is exactly what
// triggers API error 14. So polling and re-writing are separated: poll often, but only
// re-write once the settle budget has genuinely elapsed.
var (
	// verifyAttempts bounds how many times the desired state is written.
	verifyAttempts = 3
	// pollInterval is how often the read-back re-reads while a write propagates.
	pollInterval = 250 * time.Millisecond
	// settleBudget is how long to keep polling after a write before re-applying it.
	// It clears the measured 3.22s maximum with margin.
	settleBudget = 4 * time.Second
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
// read-back), otherwise apply mutate. Re-application is safe because REPLACE and
// DELETE are idempotent and a duplicate CREATE is tolerated. Bounded by
// verifyAttempts; on exhaustion it returns an error so cert-manager retries the
// challenge.
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

	// check reads the RRSet and reports whether the desired state already holds.
	// A not-found error means the record is absent, which is a legitimate state
	// rather than a failure.
	check := func() (*client.APIRRSet, bool, error) {
		existing, err := cl.GetRRSet(ctx, zone, cfg.GroupName, subdomain, "TXT")
		if err != nil {
			if !client.IsNotFound(err) {
				return nil, false, fmt.Errorf("f5xc: getting RRSet: %w", err)
			}
			existing = nil
		}
		return existing, satisfied(txtValues(existing)), nil
	}

	for attempt := 1; attempt <= verifyAttempts; attempt++ {
		existing, ok, err := check()
		if err != nil {
			return err
		}
		if ok {
			klog.V(2).InfoS("f5xc: RRSet already in desired state", "subdomain", subdomain, "attempt", attempt)
			return nil
		}

		op, rrset := mutate(existing)
		if err := applyRRSetOp(ctx, cl, cfg, zone, subdomain, op, rrset); err != nil {
			return err
		}

		// Poll for this write to land rather than re-writing on a fixed interval.
		// Every write here is read back, including the one from the final attempt.
		settled, err := waitForSettle(check)
		if err != nil {
			return err
		}
		if settled {
			return nil
		}
		klog.V(2).InfoS("f5xc: write did not settle within budget, re-applying",
			"subdomain", subdomain, "attempt", attempt)
	}

	klog.ErrorS(nil, "f5xc: RRSet did not converge",
		"zone", zone, "group", cfg.GroupName, "subdomain", subdomain, "attempts", verifyAttempts)
	return fmt.Errorf("f5xc: RRSet %q did not converge after %d attempts", subdomain, verifyAttempts)
}

// waitForSettle re-reads until the desired state holds or settleBudget elapses. It
// reports whether the state settled. Polling instead of sleeping the whole budget
// means the common case returns as soon as the write is visible, and no redundant
// write is issued while the zone is still committing the previous one.
func waitForSettle(check func() (*client.APIRRSet, bool, error)) (bool, error) {
	deadline := time.Now().Add(settleBudget)
	for {
		time.Sleep(pollInterval)
		if _, ok, err := check(); err != nil {
			return false, err
		} else if ok {
			return true, nil
		}
		if !time.Now().Before(deadline) {
			return false, nil
		}
	}
}

// applyRRSetOp performs one create/replace/delete. Errors meaning "the state is
// already what this op was moving toward" are tolerated so the loop can re-read and
// settle instead of failing the challenge.
func applyRRSetOp(
	ctx context.Context,
	cl RRSetClient,
	cfg *F5XCConfig,
	zone, subdomain string,
	op rrsetOp,
	rrset client.RRSet,
) error {
	switch op {
	case opCreate:
		if _, err := cl.CreateRRSet(ctx, zone, cfg.GroupName, rrset); err != nil {
			// A lagging read can make an existing RRSet look absent. The API rejects
			// the duplicate CREATE; the next read-back sees the record and switches
			// to REPLACE, so this is not fatal.
			if client.IsDuplicateRecord(err) {
				klog.V(2).InfoS("f5xc: RRSet already exists, reconciling on next read-back", "subdomain", subdomain)
				return nil
			}
			return fmt.Errorf("f5xc: creating RRSet: %w", err)
		}
		klog.V(2).InfoS("f5xc: created RRSet", "subdomain", subdomain, "values", len(rrset.TXTRecord.Values))
	case opReplace:
		// A not-found REPLACE means the RRSet vanished between the read and the
		// write; the next read-back decides whether to create it or stop.
		if _, err := cl.ReplaceRRSet(ctx, zone, cfg.GroupName, subdomain, "TXT", rrset); err != nil {
			if !client.IsNotFound(err) {
				return fmt.Errorf("f5xc: replacing RRSet: %w", err)
			}
			klog.V(2).InfoS("f5xc: RRSet gone before replace, reconciling on next read-back", "subdomain", subdomain)
			return nil
		}
		klog.V(2).InfoS("f5xc: replaced RRSet", "subdomain", subdomain, "values", len(rrset.TXTRecord.Values))
	case opDelete:
		if err := cl.DeleteRRSet(ctx, zone, cfg.GroupName, subdomain, "TXT"); err != nil && !client.IsNotFound(err) {
			return fmt.Errorf("f5xc: deleting RRSet: %w", err)
		}
		klog.V(2).InfoS("f5xc: deleted RRSet", "subdomain", subdomain)
	}
	return nil
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
