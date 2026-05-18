package f5xc

import (
	"encoding/json"
	"testing"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

func makeConfig(t *testing.T, obj any) *extapi.JSON {
	t.Helper()
	raw, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	return &extapi.JSON{Raw: raw}
}

func TestLoadConfig_Valid(t *testing.T) {
	cfgJSON := makeConfig(t, map[string]any{
		"tenantName": "my-tenant",
		"groupName":  "cert-manager",
		"apiTokenSecretRef": map[string]string{
			"name": "f5xc-creds",
			"key":  "api-token",
		},
	})
	cfg, err := LoadConfig(cfgJSON)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.TenantName != "my-tenant" {
		t.Errorf("tenantName = %s, want my-tenant", cfg.TenantName)
	}
	if cfg.GroupName != "cert-manager" {
		t.Errorf("groupName = %s, want cert-manager", cfg.GroupName)
	}
	if cfg.Server != "" {
		t.Errorf("server = %s, want empty", cfg.Server)
	}
	if cfg.TTL != 0 {
		t.Errorf("ttl = %d, want 0", cfg.TTL)
	}
	if cfg.APITokenSecretRef == nil || cfg.APITokenSecretRef.Name != "f5xc-creds" {
		t.Error("apiTokenSecretRef not parsed correctly")
	}
}

func TestLoadConfig_WithOptionalFields(t *testing.T) {
	cfgJSON := makeConfig(t, map[string]any{
		"tenantName": "my-tenant",
		"groupName":  "cert-manager",
		"server":     "custom.server.io",
		"ttl":        60,
		"apiTokenSecretRef": map[string]string{"name": "f5xc-creds", "key": "api-token"},
	})
	cfg, err := LoadConfig(cfgJSON)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server != "custom.server.io" {
		t.Errorf("server = %s, want custom.server.io", cfg.Server)
	}
	if cfg.TTL != 60 {
		t.Errorf("ttl = %d, want 60", cfg.TTL)
	}
}

func TestLoadConfig_NilJSON(t *testing.T) {
	_, err := LoadConfig(nil)
	if err == nil {
		t.Fatal("expected error for nil config")
	}
}

func TestLoadConfig_MissingTenant(t *testing.T) {
	cfgJSON := makeConfig(t, map[string]any{
		"groupName": "cert-manager",
		"apiTokenSecretRef": map[string]string{"name": "s", "key": "k"},
	})
	_, err := LoadConfig(cfgJSON)
	if err == nil {
		t.Fatal("expected error for missing tenantName")
	}
}

func TestLoadConfig_MissingGroupName(t *testing.T) {
	cfgJSON := makeConfig(t, map[string]any{
		"tenantName": "my-tenant",
		"apiTokenSecretRef": map[string]string{"name": "s", "key": "k"},
	})
	_, err := LoadConfig(cfgJSON)
	if err == nil {
		t.Fatal("expected error for missing groupName")
	}
}

func TestLoadConfig_NoAuth(t *testing.T) {
	cfgJSON := makeConfig(t, map[string]any{
		"tenantName": "my-tenant",
		"groupName":  "cert-manager",
	})
	_, err := LoadConfig(cfgJSON)
	if err == nil {
		t.Fatal("expected error when no auth")
	}
}

func TestLoadConfig_BothAuth_PrefersToken(t *testing.T) {
	cfgJSON := makeConfig(t, map[string]any{
		"tenantName": "my-tenant",
		"groupName":  "cert-manager",
		"apiTokenSecretRef":    map[string]string{"name": "s", "key": "k"},
		"certificateSecretRef": map[string]string{"name": "c", "p12Key": "p", "passwordKey": "pw"},
	})
	cfg, err := LoadConfig(cfgJSON)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.APITokenSecretRef == nil {
		t.Error("expected apiTokenSecretRef to be preserved")
	}
	if cfg.CertificateSecretRef != nil {
		t.Error("expected certificateSecretRef to be cleared when token is also present")
	}
}

func TestLoadConfig_CertAuth_Valid(t *testing.T) {
	cfgJSON := makeConfig(t, map[string]any{
		"tenantName": "my-tenant",
		"groupName":  "cert-manager",
		"certificateSecretRef": map[string]string{
			"name": "f5xc-cert", "p12Key": "cert.p12", "passwordKey": "password",
		},
	})
	cfg, err := LoadConfig(cfgJSON)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.CertificateSecretRef == nil {
		t.Fatal("expected certificateSecretRef to be set")
	}
	if cfg.CertificateSecretRef.Name != "f5xc-cert" {
		t.Errorf("name = %s, want f5xc-cert", cfg.CertificateSecretRef.Name)
	}
}

func TestLoadConfig_CertAuth_MissingFields(t *testing.T) {
	cfgJSON := makeConfig(t, map[string]any{
		"tenantName": "my-tenant",
		"groupName":  "cert-manager",
		"certificateSecretRef": map[string]string{"name": "f5xc-cert"},
	})
	_, err := LoadConfig(cfgJSON)
	if err == nil {
		t.Fatal("expected error for missing p12Key and passwordKey")
	}
}

func TestEffectiveTTL_Default(t *testing.T) {
	cfg := &F5XCConfig{}
	if cfg.EffectiveTTL() != 120 {
		t.Errorf("EffectiveTTL = %d, want 120", cfg.EffectiveTTL())
	}
}

func TestEffectiveTTL_Custom(t *testing.T) {
	cfg := &F5XCConfig{TTL: 60}
	if cfg.EffectiveTTL() != 60 {
		t.Errorf("EffectiveTTL = %d, want 60", cfg.EffectiveTTL())
	}
}
