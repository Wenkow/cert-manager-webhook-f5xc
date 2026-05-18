# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.2.4]: https://github.com/Wenkow/cert-manager-webhook-f5xc/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/Wenkow/cert-manager-webhook-f5xc/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/Wenkow/cert-manager-webhook-f5xc/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/Wenkow/cert-manager-webhook-f5xc/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/Wenkow/cert-manager-webhook-f5xc/compare/v0.1.3...v0.2.0
[0.1.3]: https://github.com/Wenkow/cert-manager-webhook-f5xc/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/Wenkow/cert-manager-webhook-f5xc/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/Wenkow/cert-manager-webhook-f5xc/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Wenkow/cert-manager-webhook-f5xc/releases/tag/v0.1.0
