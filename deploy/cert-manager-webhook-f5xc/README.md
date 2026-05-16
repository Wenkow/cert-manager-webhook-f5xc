# cert-manager-webhook-f5xc

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

1. **Create a Secret** containing your F5 XC API token:

   ```bash
   kubectl create secret generic f5xc-api-token \
     --namespace cert-manager \
     --from-literal=token=YOUR_F5XC_API_TOKEN
   ```

2. **Install the webhook:**

   ```bash
   helm install cert-manager-webhook-f5xc \
     oci://ghcr.io/wenkow/charts/cert-manager-webhook-f5xc \
     --namespace cert-manager
   ```

## Configuration

Create a `ClusterIssuer` (or `Issuer`) that references the webhook solver.
Note that `groupName` appears twice in the YAML — at the `webhook` level it is a fixed identifier
that tells cert-manager which webhook to call (always `acme.f5xc.io`), while inside `config`
it is the name of the RRSet group in your F5 XC DNS zone:

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-f5xc-prod
spec:
  acme:
    email: you@example.com
    server: https://acme-v02.api.letsencrypt.org/directory
    privateKeySecretRef:
      name: letsencrypt-f5xc-prod-account-key
    solvers:
      - dns01:
          webhook:
            # These two fields are fixed — they tell cert-manager which webhook to call.
            groupName: acme.f5xc.io
            solverName: f5xc
            # Everything below is passed to the webhook as solver configuration.
            config:
              tenantName: my-tenant
              # RRSet group name in your F5 XC DNS zone (lowercase, digits, hyphens only).
              # You can choose any name — F5 XC will create the group automatically.
              groupName: "cert-manager"
              # server: "console.ves.volterra.io"
              # ttl: 120
              apiTokenSecretRef:
                name: f5xc-api-token
                key: token
```

### Configuration Fields

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `tenantName` | Yes | - | Your F5 XC tenant name (e.g. `my-tenant`). Used to construct the API base URL. |
| `groupName` | Yes | - | RRSet group name in your F5 XC DNS zone. Must contain only lowercase letters, digits, and hyphens. |
| `server` | No | `console.ves.volterra.io` | Override the F5 XC console domain. |
| `ttl` | No | `120` | TTL in seconds for DNS TXT records. |
| `apiTokenSecretRef.name` | Yes | - | Name of the Kubernetes Secret containing the F5 XC API token. |
| `apiTokenSecretRef.key` | Yes | - | Key within the Secret that holds the API token value. |

> **Note:** Certificate-based authentication (`certificateSecretRef`) is planned but not yet implemented.

## Usage

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: example-tls
  namespace: default
spec:
  secretName: example-tls
  issuerRef:
    name: letsencrypt-f5xc-prod
    kind: ClusterIssuer
  dnsNames:
    - example.com
    - "*.example.com"
```

## Upgrade

```bash
helm upgrade cert-manager-webhook-f5xc \
  oci://ghcr.io/wenkow/charts/cert-manager-webhook-f5xc \
  --namespace cert-manager
```

## Uninstall

```bash
helm uninstall cert-manager-webhook-f5xc --namespace cert-manager
```

## Links

- [GitHub Repository](https://github.com/Wenkow/cert-manager-webhook-f5xc)
- [cert-manager Documentation](https://cert-manager.io/docs/)
- [F5 Distributed Cloud](https://www.f5.com/cloud)
