package f5xc

import (
	"context"
	"fmt"
	"strings"

	acme "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"

	"github.com/wenkow/cert-manager-webhook-f5xc/f5xc/client"
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

// clientFactory constructs an RRSetClient from a config and API token.
type clientFactory func(cfg *F5XCConfig, token string) (RRSetClient, error)

// Solver implements the cert-manager webhook.Solver interface for F5 XC DNS.
type Solver struct {
	clientFactory clientFactory
	secretReader  SecretReader
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

// Present creates or appends a TXT record for the ACME challenge.
func (s *Solver) Present(ch *acme.ChallengeRequest) error {
	cfg, cl, err := s.setup(ch)
	if err != nil {
		return err
	}

	ctx := context.Background()
	zone := unFQDN(ch.ResolvedZone)
	subdomain := extractSubDomain(ch.ResolvedFQDN, ch.ResolvedZone)

	existing, err := cl.GetRRSet(ctx, zone, cfg.GroupName, subdomain, "TXT")
	if err != nil {
		return fmt.Errorf("f5xc: getting existing RRSet: %w", err)
	}

	if existing == nil {
		// No existing record: create a new one.
		rrset := client.RRSet{
			TTL: cfg.EffectiveTTL(),
			TXTRecord: &client.TXTRecord{
				Name:   subdomain,
				Values: []string{ch.Key},
			},
		}
		if _, err := cl.CreateRRSet(ctx, zone, cfg.GroupName, rrset); err != nil {
			return fmt.Errorf("f5xc: creating RRSet: %w", err)
		}
		return nil
	}

	// Record exists: append the new value.
	values := existing.RRSet.TXTRecord.Values
	values = append(values, ch.Key)
	rrset := client.RRSet{
		TTL: cfg.EffectiveTTL(),
		TXTRecord: &client.TXTRecord{
			Name:   subdomain,
			Values: values,
		},
	}
	if _, err := cl.ReplaceRRSet(ctx, zone, cfg.GroupName, subdomain, "TXT", rrset); err != nil {
		return fmt.Errorf("f5xc: replacing RRSet: %w", err)
	}
	return nil
}

// CleanUp removes the TXT record for the ACME challenge.
func (s *Solver) CleanUp(ch *acme.ChallengeRequest) error {
	cfg, cl, err := s.setup(ch)
	if err != nil {
		return err
	}

	ctx := context.Background()
	zone := unFQDN(ch.ResolvedZone)
	subdomain := extractSubDomain(ch.ResolvedFQDN, ch.ResolvedZone)

	if err := cl.DeleteRRSet(ctx, zone, cfg.GroupName, subdomain, "TXT"); err != nil {
		return fmt.Errorf("f5xc: deleting RRSet: %w", err)
	}
	return nil
}

// setup is shared logic: load config, read secret, build client.
func (s *Solver) setup(ch *acme.ChallengeRequest) (*F5XCConfig, RRSetClient, error) {
	cfg, err := LoadConfig(ch.Config)
	if err != nil {
		return nil, nil, err
	}

	secretData, err := s.secretReader.GetSecretData(ch.ResourceNamespace, cfg.APITokenSecretRef.Name)
	if err != nil {
		return nil, nil, fmt.Errorf("f5xc: reading secret %s/%s: %w", ch.ResourceNamespace, cfg.APITokenSecretRef.Name, err)
	}

	tokenBytes, ok := secretData[cfg.APITokenSecretRef.Key]
	if !ok {
		return nil, nil, fmt.Errorf("f5xc: key %q not found in secret %s/%s", cfg.APITokenSecretRef.Key, ch.ResourceNamespace, cfg.APITokenSecretRef.Name)
	}

	cl, err := s.clientFactory(cfg, string(tokenBytes))
	if err != nil {
		return nil, nil, fmt.Errorf("f5xc: creating API client: %w", err)
	}

	return cfg, cl, nil
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

// defaultClientFactory creates a real F5 XC API client with token auth.
func defaultClientFactory(cfg *F5XCConfig, token string) (RRSetClient, error) {
	auth := &client.TokenAuth{Token: token}
	c, err := client.NewClient(cfg.TenantName, cfg.Server, auth)
	if err != nil {
		return nil, err
	}
	return &clientAdapter{client: c}, nil
}

// clientAdapter adapts client.Client to the RRSetClient interface.
// The real client's Create/Replace take APIRRSet; the solver interface uses RRSet.
type clientAdapter struct {
	client *client.Client
}

func (a *clientAdapter) GetRRSet(ctx context.Context, zone, group, name, recordType string) (*client.APIRRSet, error) {
	return a.client.GetRRSet(ctx, zone, group, name, recordType)
}

func (a *clientAdapter) CreateRRSet(ctx context.Context, zone, group string, rrset client.RRSet) (*client.APIRRSet, error) {
	return a.client.CreateRRSet(ctx, zone, group, client.APIRRSet{RRSet: rrset})
}

func (a *clientAdapter) ReplaceRRSet(ctx context.Context, zone, group, name, recordType string, rrset client.RRSet) (*client.APIRRSet, error) {
	return a.client.ReplaceRRSet(ctx, zone, group, name, recordType, client.APIRRSet{RRSet: rrset})
}

func (a *clientAdapter) DeleteRRSet(ctx context.Context, zone, group, name, recordType string) error {
	return a.client.DeleteRRSet(ctx, zone, group, name, recordType)
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
