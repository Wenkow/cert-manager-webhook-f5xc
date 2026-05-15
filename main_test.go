//go:build conformance

package main

import (
	"os"
	"testing"

	acmetest "github.com/cert-manager/cert-manager/test/acme"

	"github.com/wenkow/cert-manager-webhook-f5xc/f5xc"
)

var zone = os.Getenv("TEST_ZONE_NAME")

func TestRunsSuite(t *testing.T) {
	if zone == "" {
		t.Skip("TEST_ZONE_NAME not set, skipping conformance tests")
	}

	solver := f5xc.NewSolver()

	fixture := acmetest.NewFixture(solver,
		acmetest.SetResolvedZone(zone),
		acmetest.SetAllowAmbientCredentials(false),
		acmetest.SetManifestPath("testdata/f5xc"),
	)

	fixture.RunBasic(t)
	fixture.RunExtended(t)
}
