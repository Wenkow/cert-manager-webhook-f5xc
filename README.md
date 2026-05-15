# cert-manager-webhook-f5xc

[![CI](https://github.com/wenkow/cert-manager-webhook-f5xc/actions/workflows/ci.yaml/badge.svg)](https://github.com/wenkow/cert-manager-webhook-f5xc/actions/workflows/ci.yaml)

An external [cert-manager](https://cert-manager.io/) DNS01 webhook solver for
[F5 Distributed Cloud](https://www.f5.com/cloud). This webhook allows
cert-manager to automatically create and clean up DNS TXT records in F5 XC
when solving ACME DNS01 challenges, enabling fully automated TLS certificate
issuance for domains managed by F5 Distributed Cloud DNS.

## Prerequisites

- Kubernetes cluster with [cert-manager](https://cert-manager.io/docs/installation/) installed
- Helm 3.8+
- An F5 Distributed Cloud tenant with API access
- An F5 XC API token (generated from the F5 XC console)

## Installation

1. **Create a Secret** containing your F5 XC API token in the cert-manager namespace:

   ```bash
   kubectl create secret generic f5xc-api-token \
     --namespace cert-manager \
     --from-literal=token=YOUR_F5XC_API_TOKEN
   ```

2. **Install the webhook** using the Helm OCI chart:

   ```bash
   helm install cert-manager-webhook-f5xc \
     oci://ghcr.io/wenkow/cert-manager-webhook-f5xc \
     --version 0.1.2 \
     --namespace cert-manager
   ```

## Configuration

Create a `ClusterIssuer` (or `Issuer`) that references the webhook solver.
The solver configuration is specified inline under `solvers[].dns01.webhook.config`:

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    email: you@example.com
    server: https://acme-v02.api.letsencrypt.org/directory
    privateKeySecretRef:
      name: letsencrypt-prod-account-key
    solvers:
      - dns01:
          webhook:
            groupName: acme.f5xc.io
            solverName: f5xc
            config:
              tenantName: my-tenant
              groupName: acme.f5xc.io
              # server: https://my-tenant.console.ves.volterra.io/api
              # ttl: 120
              apiTokenSecretRef:
                name: f5xc-api-token
                key: token
```

### Configuration Fields

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `tenantName` | Yes | - | Your F5 XC tenant name (e.g. `my-tenant`). Used to construct the API base URL if `server` is not set. |
| `groupName` | Yes | - | The webhook solver group name. Must match the `groupName` value in `values.yaml` (default `acme.f5xc.io`). |
| `server` | No | `https://<tenantName>.console.ves.volterra.io/api` | Override the F5 XC API base URL. Useful for custom or private endpoints. |
| `ttl` | No | `120` | TTL in seconds for DNS TXT records created during challenges. |
| `apiTokenSecretRef.name` | Yes | - | Name of the Kubernetes Secret containing the F5 XC API token. |
| `apiTokenSecretRef.key` | Yes | - | Key within the Secret that holds the API token value. |
| `certificateSecretRef` | No | - | **Planned but not yet implemented.** Will support P12 certificate-based authentication in a future release. |

## Usage

Once the `ClusterIssuer` is configured, create a `Certificate` resource to request a TLS certificate:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: example-tls
  namespace: default
spec:
  secretName: example-tls
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  dnsNames:
    - example.com
    - "*.example.com"
```

When cert-manager processes this Certificate, it will:

1. Create an ACME order with the configured ACME server.
2. Call the F5 XC webhook to create a DNS TXT record (`_acme-challenge.example.com`) in your F5 XC tenant.
3. Wait for the ACME server to verify the DNS record.
4. Call the webhook to clean up the TXT record after validation succeeds.
5. Store the issued certificate in the `example-tls` Secret.

## Uninstall

```bash
helm uninstall cert-manager-webhook-f5xc --namespace cert-manager
kubectl delete secret f5xc-api-token --namespace cert-manager
```

## Development

See [DEVELOPMENT.md](DEVELOPMENT.md) for build, test, and release instructions.
