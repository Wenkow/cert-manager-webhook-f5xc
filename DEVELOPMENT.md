# Development

## Prerequisites

- [Go](https://go.dev/dl/) 1.26
- [Docker](https://docs.docker.com/get-docker/)
- [Helm](https://helm.sh/docs/intro/install/) 3

## Repository Layout

```
.
├── main.go                       # Webhook server entry point
├── main_test.go                  # Conformance test runner (build tag: conformance)
├── f5xc/
│   ├── solver.go                 # DNS01 solver (Present, CleanUp, Initialize)
│   ├── solver_test.go            # Solver unit tests
│   ├── config.go                 # Config parsing and validation
│   ├── config_test.go            # Config unit tests
│   └── client/
│       ├── client.go             # F5 XC REST API client
│       ├── client_test.go        # Client unit tests
│       ├── auth.go               # API authentication helpers
│       ├── auth_test.go          # Auth unit tests
│       └── types.go              # API request/response types
├── deploy/
│   └── cert-manager-webhook-f5xc/
│       ├── Chart.yaml            # Helm chart metadata
│       ├── values.yaml           # Default Helm values
│       └── templates/            # Kubernetes manifests
├── testdata/
│   └── f5xc/
│       └── config.json           # Test fixture for conformance tests
├── Dockerfile                    # Multi-stage build with distroless runtime
├── Makefile                      # Build, test, docker, and deploy targets
├── go.mod                        # Go module definition
└── go.sum                        # Go dependency checksums
```

## Build

```bash
make build
```

This compiles the webhook binary with trimmed paths and stripped symbols.

## Unit Tests

Run all unit tests:

```bash
make test
```

Run tests for a specific package:

```bash
go test -v ./f5xc/client/...
```

## Conformance Tests

The conformance tests exercise the webhook against a real (or envtest-provided)
Kubernetes API server. They are gated behind the `conformance` build tag to
avoid init-time panics when envtest binaries are not present.

1. Set up the envtest binaries:

   ```bash
   make setup-envtest
   ```

2. Edit `testdata/f5xc/config.json` with valid F5 XC credentials and
   configuration for your test tenant.

3. Export the test zone:

   ```bash
   export TEST_ZONE_NAME=example.com.
   ```

4. Run the conformance suite:

   ```bash
   make test-conformance
   ```

> **Note:** The conformance tests use the `conformance` build tag. They will
> not run with a plain `go test ./...` invocation.

## Docker

Build the Docker image locally:

```bash
make docker-build
```

Build and push to the registry:

```bash
make docker-push
```

> **Note:** You must be logged in to `ghcr.io` before pushing:
>
> ```bash
> echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin
> ```

## Helm

Lint the Helm chart:

```bash
helm lint deploy/cert-manager-webhook-f5xc
```

Render templates locally for inspection:

```bash
helm template cert-manager-webhook-f5xc deploy/cert-manager-webhook-f5xc
```

## Local Deployment

Deploy to a local [kind](https://kind.sigs.k8s.io/) cluster:

1. Build the Docker image:

   ```bash
   make docker-build
   ```

2. Load the image into the kind cluster:

   ```bash
   kind load docker-image ghcr.io/wenkow/cert-manager-webhook-f5xc:latest
   ```

3. Install with Helm:

   ```bash
   make deploy
   ```

4. To upgrade after rebuilding:

   ```bash
   helm upgrade cert-manager-webhook-f5xc deploy/cert-manager-webhook-f5xc \
     --namespace cert-manager \
     --set image.repository=ghcr.io/wenkow/cert-manager-webhook-f5xc \
     --set image.tag=latest
   ```

5. To uninstall:

   ```bash
   make undeploy
   ```

## Release Process

Releases are automated via GitHub Actions. 

The release workflow will automatically:

- Run unit tests
- Build and push multi-arch Docker images (`amd64`, `arm64`, `arm/v7`)
- Package and push the Helm chart as an OCI artifact to `ghcr.io`
- Create a GitHub Release with auto-generated release notes and the chart
  archive attached as an asset
