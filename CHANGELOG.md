# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.2] - 2026-07-10

### Security

- Upgrade `software.sslmate.com/src/go-pkcs12` to v0.7.2 — fixes GO-2026-5052. The vulnerable code is reached via P12 certificate authentication (`NewCertAuth` → `pkcs12.DecodeChain`).
- Upgrade Go toolchain to 1.26.5 — fixes GO-2026-5856 (Encrypted Client Hello privacy leak in `crypto/tls`), reached through the webhook TLS server and the F5 XC API HTTPS client.

## [0.4.1] - 2026-06-16

### Fixed

- Certificate (P12) authentication no longer sets `RootCAs` from the client chain inside the P12. The F5 XC API server certificate is verified against the system trust store, removing a fallback (`SystemCertPool()`-or-empty) that could silently drop all public roots and fail server verification. The P12's CA certs remain attached to the client certificate chain presented during the mTLS handshake.
- `DeleteRRSet` now retries on the transient error code 14 (`Previous DNS zone change is pending`), matching `CreateRRSet`/`ReplaceRRSet`. Issuing several certificates at once queues rapid zone changes, and the un-retried delete previously failed cleanup with that error.
- The chart's container image tag now defaults to the chart `appVersion` instead of the floating `latest`. Previously a `helm upgrade` left the rendered Deployment unchanged (`:latest`), so no rollout happened and—combined with `pullPolicy: IfNotPresent`—no new image was pulled. Override `image.tag` to pin a specific tag.

## [0.4.0] - 2026-06-16

### Fixed

- `Present` is now idempotent: it no longer appends a challenge value that already exists in the RRSet. Previously, retries and multiple certificates issued at once produced duplicate values, which F5 XC rejects with HTTP 400 (`values should be unique`).
- `CleanUp` now removes only its own challenge value instead of deleting the entire RRSet. When several challenges share one TXT record (e.g. apex + wildcard SANs), the old behavior clobbered the other values and sent the remaining challenge into a `not found` retry loop, deadlocking the finalizer.
- `CleanUp` treats a missing record (HTTP 404 / F5 XC API code 5 `NOT_FOUND`) as success, making the operation idempotent.

### Added

- Structured logging (`klog`) in `Present`/`CleanUp` and the F5 XC API client. Run with `-v=2` for operation-level logs and `-v=4` for per-request/response logs.

## [0.3.3] - 2026-06-03

### Security

- Upgrade Go toolchain to 1.26.4 — fixes GO-2026-5037 (crypto/x509 inefficient candidate hostname parsing), GO-2026-5038 (mime quadratic complexity in `WordDecoder.DecodeHeader`), and GO-2026-5039 (net/textproto unescaped inputs in errors)

## [0.3.2] - 2026-05-25

### Security

- Upgrade golang.org/x/net to v0.55.0 — fixes CVE-2026-27136, CVE-2026-42506, CVE-2026-42502, CVE-2026-25680, CVE-2026-25681 (html tokenizer sanitizer bypasses), GO-2026-4918 (HTTP/2 SETTINGS_MAX_FRAME_SIZE infinite loop), and QUIC buffer/race fixes

## [0.3.1] - 2026-05-22

### Security

- Upgrade golang.org/x/crypto to v0.52.0

## [0.3.0] - 2026-05-20

### Added

- P12 certificate-based authentication as alternative to API token (`certificateSecretRef`)
- When both auth methods are configured, token takes precedence
- Troubleshooting section in DEVELOPMENT.md

## [0.2.4] - 2026-05-16

### Security

- Upgrade OpenTelemetry to v1.43.0 (fixes CVE-2026-39883, CVE-2026-29181, CVE-2026-24051)

### Changed

- Add `oras` push of `artifacthub-repo.yml` to release workflow for Artifact Hub verified publisher badge

## [0.2.3] - 2026-05-16

### Fixed

- Include `artifacthub-repo.yml` inside chart package for Artifact Hub verified publisher badge

## [0.2.2] - 2026-05-16

### Security

- Upgrade Go from 1.23 to 1.26 (fixes CVE-2025-68121 crypto/tls, archive/tar unbounded allocation)
- Upgrade google.golang.org/grpc from v1.69.2 to v1.79.3 (fixes CVE-2026-33186 authorization bypass)

## [0.2.1] - 2026-05-16

### Added

- Artifact Hub badge in project README

### Changed

- Artifact Hub category set to `security`
- Container image metadata with platform list (amd64, arm64, arm/v7)

## [0.2.0] - 2026-05-15

### Fixed

- Clarified the two `groupName` fields in Issuer YAML example (webhook API group vs F5 XC RRSet group)
- Fixed `config.groupName` description in configuration table

## [0.1.3] - 2026-05-15

### Fixed

- Push Helm chart to separate OCI path (`oci://ghcr.io/wenkow/charts`) to avoid conflict with Docker image

### Changed

- Use Go native cross-compilation instead of QEMU emulation (~4x faster multi-arch builds)

## [0.1.2] - 2026-05-15

### Changed

- Upgrade all GitHub Actions to Node.js 24 compatible versions (checkout v6, setup-go v6, setup-helm v5, docker actions v4/v6/v7, golangci-lint-action v7, action-gh-release v3)

## [0.1.1] - 2026-05-15

### Fixed

- Correct Helm OCI push path to avoid nested package name

## [0.1.0] - 2026-05-15

### Initial release 

### Added

- External cert-manager DNS01 webhook solver for F5 Distributed Cloud
- F5 XC RRSet API client with Create, Get, Replace, Delete operations
- Retry logic for transient F5 XC 503 errors (code 14: "previous DNS zone change is pending")
- Token-based authentication (`apiTokenSecretRef`)
- Config validation with auth method exclusivity check
- Solver supports creating new TXT records and appending to existing ones
- Helm chart with RBAC, PKI chain, Deployment, Service, APIService

[0.4.2]: https://github.com/Wenkow/cert-manager-webhook-f5xc/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/Wenkow/cert-manager-webhook-f5xc/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/Wenkow/cert-manager-webhook-f5xc/compare/v0.3.3...v0.4.0
[0.3.3]: https://github.com/Wenkow/cert-manager-webhook-f5xc/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/Wenkow/cert-manager-webhook-f5xc/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/Wenkow/cert-manager-webhook-f5xc/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/Wenkow/cert-manager-webhook-f5xc/compare/v0.2.4...v0.3.0
[0.2.4]: https://github.com/Wenkow/cert-manager-webhook-f5xc/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/Wenkow/cert-manager-webhook-f5xc/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/Wenkow/cert-manager-webhook-f5xc/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/Wenkow/cert-manager-webhook-f5xc/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/Wenkow/cert-manager-webhook-f5xc/compare/v0.1.3...v0.2.0
[0.1.3]: https://github.com/Wenkow/cert-manager-webhook-f5xc/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/Wenkow/cert-manager-webhook-f5xc/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/Wenkow/cert-manager-webhook-f5xc/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Wenkow/cert-manager-webhook-f5xc/releases/tag/v0.1.0
