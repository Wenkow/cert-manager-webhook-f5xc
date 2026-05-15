package f5xc

import (
	"encoding/json"
	"errors"
	"fmt"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

const defaultTTL = 120

type F5XCConfig struct {
	TenantName           string             `json:"tenantName"`
	GroupName            string             `json:"groupName"`
	Server               string             `json:"server,omitempty"`
	TTL                  int                `json:"ttl,omitempty"`
	APITokenSecretRef    *SecretKeySelector `json:"apiTokenSecretRef,omitempty"`
	CertificateSecretRef *CertSecretRef     `json:"certificateSecretRef,omitempty"`
}

type SecretKeySelector struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

type CertSecretRef struct {
	Name        string `json:"name"`
	P12Key      string `json:"p12Key"`
	PasswordKey string `json:"passwordKey"`
}

func LoadConfig(cfgJSON *extapi.JSON) (*F5XCConfig, error) {
	if cfgJSON == nil {
		return nil, errors.New("f5xc: solver config is required")
	}
	cfg := &F5XCConfig{}
	if err := json.Unmarshal(cfgJSON.Raw, cfg); err != nil {
		return nil, fmt.Errorf("f5xc: decoding solver config: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *F5XCConfig) validate() error {
	if c.TenantName == "" {
		return errors.New("f5xc: tenantName is required")
	}
	if c.GroupName == "" {
		return errors.New("f5xc: groupName is required")
	}
	hasToken := c.APITokenSecretRef != nil
	hasCert := c.CertificateSecretRef != nil
	if !hasToken && !hasCert {
		return errors.New("f5xc: one of apiTokenSecretRef or certificateSecretRef is required")
	}
	if hasToken && hasCert {
		return errors.New("f5xc: only one of apiTokenSecretRef or certificateSecretRef may be specified")
	}
	if hasCert {
		return errors.New("f5xc: certificate authentication is not yet implemented")
	}
	if c.APITokenSecretRef.Name == "" || c.APITokenSecretRef.Key == "" {
		return errors.New("f5xc: apiTokenSecretRef requires both name and key")
	}
	return nil
}

func (c *F5XCConfig) EffectiveTTL() int {
	if c.TTL > 0 {
		return c.TTL
	}
	return defaultTTL
}
