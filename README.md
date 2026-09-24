# cert-manager-webhook-f5xc

[![CI](https://github.com/wenkow/cert-manager-webhook-f5xc/actions/workflows/ci.yaml/badge.svg)](https://github.com/wenkow/cert-manager-webhook-f5xc/actions/workflows/ci.yaml)
[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/cert-manager-webhook-f5xc)](https://artifacthub.io/packages/search?repo=cert-manager-webhook-f5xc)

An external [cert-manager](https://cert-manager.io/) DNS01 webhook solver for
[F5 Distributed Cloud](https://www.f5.com/cloud). It creates and removes the
`_acme-challenge` TXT records an ACME DNS01 challenge requires, so cert-manager
can issue certificates for domains hosted in F5 Distributed Cloud DNS.

## Prerequisites

- Kubernetes cluster with [cert-manager](https://cert-manager.io/docs/installation/) installed
- Helm 3.8+
- An F5 Distributed Cloud tenant with API access
- An F5 XC API token **or** a P12 client certificate (both generated from the F5 XC console)

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
     oci://ghcr.io/wenkow/charts/cert-manager-webhook-f5xc \
     --version 0.6.0 \
     --namespace cert-manager
   ```

## Single replica

The chart runs one replica and uses the `Recreate` strategy. The solver serializes
concurrent challenges for the same FQDN with an in-process lock, so a second pod can
overwrite the TXT record written by the first. Do not scale the Deployment up.
Upgrades stop the webhook briefly instead of running two pods at once; cert-manager
retries any challenge that hits the gap.

## Configuration

Create a `ClusterIssuer` (or `Issuer`) that references the webhook solver.
`groupName` appears twice in the YAML. At the `webhook` level it is a fixed
identifier telling cert-manager which webhook to call (always `acme.f5xc.io`).
Inside `config` it is the name of the RRSet group in your F5 XC DNS zone.

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
            # These two fields are fixed. They tell cert-manager which webhook to call.
            groupName: acme.f5xc.io
            solverName: f5xc
            # Everything below is passed to the webhook as solver configuration.
            config:
              tenantName: my-tenant
              # RRSet group name in your F5 XC DNS zone (lowercase, digits, hyphens only).
              # Any name works. F5 XC creates the group automatically.
              groupName: "cert-manager"
              # server: "console.ves.volterra.io"
              # ttl: 120
              apiTokenSecretRef:
                name: f5xc-api-token
                key: token
```

### Configuration fields

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `tenantName` | Yes | - | Your F5 XC tenant name (e.g. `my-tenant`). Used to construct the API base URL. |
| `groupName` | Yes | - | RRSet group name in your F5 XC DNS zone. Must contain only lowercase letters, digits, and hyphens. Find it in F5 XC console under DNS Management > DNS Zones > your zone > RR Set Groups. |
| `server` | No | `console.ves.volterra.io` | Override the F5 XC console domain. |
| `ttl` | No | `120` | TTL in seconds for DNS TXT records created during challenges. |
| `apiTokenSecretRef.name` | With token auth | - | Name of the Kubernetes Secret containing the F5 XC API token. |
| `apiTokenSecretRef.key` | With token auth | - | Key within the Secret that holds the API token value. |
| `certificateSecretRef` | With P12 auth | - | P12 certificate authentication. See below. |

Set either `apiTokenSecretRef` or `certificateSecretRef`. The webhook rejects a config with neither.

<details>
<summary>Using P12 certificate authentication instead of API token</summary>

Create a Secret containing your P12 certificate and its password:

```bash
kubectl create secret generic f5xc-api-cert \
  --namespace cert-manager \
  --from-file=cert.p12=/path/to/your/certificate.p12 \
  --from-literal=password=YOUR_P12_PASSWORD
```

Reference it in the Issuer config instead of `apiTokenSecretRef`:

```yaml
            config:
              tenantName: my-tenant
              groupName: "cert-manager"
              certificateSecretRef:
                name: f5xc-api-cert
                p12Key: cert.p12
                passwordKey: password
```

The `certificateSecretRef` requires three fields: `name` (Secret name), `p12Key` (key holding the PKCS#12 bundle), and `passwordKey` (key holding the P12 password).

If both `apiTokenSecretRef` and `certificateSecretRef` are present, token authentication takes precedence.

</details>

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
    name: letsencrypt-f5xc-prod
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

## Upgrade

```bash
helm upgrade cert-manager-webhook-f5xc \
  oci://ghcr.io/wenkow/charts/cert-manager-webhook-f5xc \
  --version 0.6.0 \
  --namespace cert-manager
```

## Logging

The webhook logs through `klog`. By default only warnings and errors are emitted.
Raise verbosity via `extraArgs` to see what the solver does with each challenge:

```bash
helm upgrade cert-manager-webhook-f5xc \
  oci://ghcr.io/wenkow/charts/cert-manager-webhook-f5xc \
  --version 0.6.0 \
  --namespace cert-manager \
  --set 'extraArgs={-v=2}'
```

- `-v=2`: what the solver does with each record, such as created, replaced, deleted, already correct, or re-applied after a read-back.
- `-v=4`: every F5 XC API call, with method, path, and response status.

## Uninstall

```bash
helm uninstall cert-manager-webhook-f5xc --namespace cert-manager
kubectl delete secret f5xc-api-token --namespace cert-manager
```

## Development

See [DEVELOPMENT.md](DEVELOPMENT.md) for build and test instructions.
