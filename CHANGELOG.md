# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Add a `SECURITY.md` security policy documenting how to report a vulnerability privately. GitHub private vulnerability reporting is the channel, with the Linux Foundation's reporting guidance as the route for anything broader than this repository.
- Add a Dependabot configuration for the Go modules, the OpenAPI generator Maven plugin, the Docker base images and GitHub Actions, with grouped update pull requests and a 30-day cooldown on version updates.

## [1.4.2] - 2026-07-30

### Changed
- Rename the Go module path and all repository references from the archived Hyperledger Labs location to `github.com/lfdt-smoot` (#3).

## [1.4.1] - 2026-07-02

### Added
- Expose the `eth_signTypedData` JSON-RPC method for EIP-712 typed data signing, granted to the `transaction-signer` role. A typed data domain that declares a `chainId` other than the application's default chain is rejected.

### Security
- Extend per-account authorization to `eth_signTypedData` so a user can only sign with accounts they are authorized to use.

## [1.4.0] - 2026-07-01

### Changed
- Review/Refactor EIP712 endpoint for signare so that it can be merged.
- Change and improve repository documentation like changelog, readme, create issue templates, etc.
- Stop committing the 30MB `openapi-generator-cli.jar`; the codegen Makefile now fetches the pom-pinned version from Maven Central and verifies a recorded SHA-256 before use.
- Bump key dependencies (`btcec/v2` to `v2.5.0`, `go-sqlite3` to `v1.14.47`, `client_golang` to `v1.23.2`) to current minor versions, and add Dependabot covering the three Go modules, the Maven plugin, and the Docker base images.
- Repository hygiene: annotate the SoftHSM test key and PINs as throwaway test-only vectors and add a scoped gitleaks allowlist; replace the unversioned, reformatted vendored Swagger UI bundle with the canonical upstream 5.15.2 dist pinned by SHA-256 with provenance; and fix docs/build drift (README and code-standards tool names, Make target names, de-duplicated CHANGELOG via a build-step copy).

### Fixed
- Fixed local key vault deriving the wrong Ethereum address when a public-key coordinate had a leading zero byte.
- Fixed storage and referential-integrity errors being silently swallowed or returned via the wrong variable: failed dependency cleanup now aborts resource deletion, list queries report row-iteration failures instead of returning truncated results as success, and storage adapters propagate the correct error.
- Close the database connection pool during graceful shutdown so rapid restarts no longer leave server-side Postgres backends lingering until they time out; give the Prometheus metrics server the same `WriteTimeout`/`ReadTimeout`/`IdleTimeout` as the main and RPC servers to bound slow-body and idle keep-alive connections; and shut the servers down with a fresh time-bounded context so in-flight requests are drained instead of being abandoned by the already-cancelled shutdown context.
- Validate backend (HSM/AKV/LKV) signatures in the connector immediately after signing (64-byte `r||s` with `r` and `s` in `[1, N-1]`); a malformed backend response now returns a clear bad-gateway error (an upstream fault) instead of a misleading recovery-loop failure.
- Enforce a default and maximum page size on every list endpoint so an omitted or zero `limit` returns a bounded page instead of materializing the whole table, and reject `limit`/`offset` query values outside the 32-bit range instead of silently wrapping them.

### Security
- Fix privilege escalation where an `application-admin` could assign the `signer-admin` role to application users and gain full administrator control. Application user management now only accepts application-scoped roles, and the authorization layer denies admin actions for application-scoped requests.
- Bound the forbidden-access metric's `action` label to registered JSON-RPC methods, preventing a client from creating unbounded Prometheus label cardinality, or cause metrics cardinality DoS.
- Enforce request body and header size limits on the RPC and REST entrypoints, closing an unauthenticated memory-exhaustion vector where the pre-authentication JSON-RPC batch read buffered an arbitrarily large body. Request bodies are now bounded by a configurable `MaxBytesReader`, `MaxHeaderBytes` is set on every server, and JSON-RPC batch element count is capped.
- Sanitize authorization middleware error responses. Denied requests now return a constant generic message instead of internal error text or user/application identifiers, with the detail retained only in server-side logs keyed by a traceable id. A router no-match now returns an explicit `404` instead of an empty `200`, and the empty-action validation message was corrected to reference the action.
- Reject non-positive chain IDs so legacy (type 0) transactions can no longer produce an EIP-155 signed hash with a pre-EIP-155 `v`, which recovered the wrong sender. Application create and edit now require a chain ID `>= 1`, and the signing path rejects a non-positive chain ID for every transaction type.
- Remove a latent SQL injection risk in the persistence query-builder filter API. The value-interpolating `BetweenFilter` and `ListEqualFilter` (which had no callers) were removed so no filter interpolates a value, filter column identifiers are validated before use, and `ORDER BY` is rendered from a validated allow-list. An unrecognised order direction now returns a `400` instead of being silently sorted descending.
- Clear all reachable `govulncheck` findings in the TLS and database code paths by upgrading the Go toolchain to `v1.25.11`, `golang.org/x/net` to `v0.55.0`, and `jackc/pgx/v5` to `v5.9.2`.

### Fixed
- Fixed dagger errors.

## [1.3.0] - 2026-05-11

### Added
- Added support for signing EIP-1559 (type 2) transactions, including `maxFeePerGas` and `maxPriorityFeePerGas` fields.
- Added automatic transaction type identification based on the fields provided in the `eth_signTransaction` request.
- Signing requests with ambiguous gas parameters (e.g. mixing legacy `gasPrice` with EIP-1559 fields) are now rejected with an explicit error.
- Unsupported transaction types (e.g. type 3 EIP-4844 or type 4 EIP-7702) are now rejected with a clear unsupported error.

### Fixed
- Fixed use of lexicographic string comparison of hex values when validating `maxFeePerGas` > `maxPriorityFeePerGas`.

## [1.2.5-adhara] - 2025-11-19

### Changed
- Updated Go version to `v1.25.3`.

### Fixed
- Upgraded dependency to fix vulnerability `golang.org/x/crypto v0.36.0` => `v0.43.0`

## [1.2.4-adhara] - 2025-08-28

### Changed
- The `cfg_application` table rename the `chain_id` to `default_chain_id`
- Signare uses the `default_chain_id` when it gets a request to sign a tx (`eth_signTransaction` method) without defining the `chainId` parameter in the body.

### Added
- Added `chainId` as parameter in the rpc method `eth_signTransaction` parameters.

## [1.2.3-adhara] - 2025-08-08

### Changed
- Updated Go version to `v1.24.6`.

## [1.2.2-adhara] - 2025-06-13

### Changed
- Updated Go version to `v1.24.4`.

## [1.2.1-adhara] - 2025-04-15

### Changed
- Updated Go version to `v1.23.8`.

## [1.2.0-adhara] - 2025-03-18

### Added
- Added Local Key Vault (LKV) as a new supported Hardware Security Module kind for local testing and development.

### Changed
- Env variable used to override static configuration attributes changed to `SIGNARE`.

### Fixed
- Upgraded dependency to fix vulnerability `golang.org/x/crypto v0.24.0` => `v0.31.0`
- Upgraded indirect dependency to fix vulnerability `golang.org/x/net v0.26.0 ` => `v0.33.0`
- Updated to Go v1.23.7 to address security issues.
- RLP encoding issue in arm64 architectures.

## [1.1.0] - 2024-08-28

### Added
- Added integration with Azure Key Vault as a partial module (only signing).

## [1.0.1] - 2024-08-06

### Added
- None.

### Changed
- Dockerfile base Docker image change from golang to scratch.

### Deprecated
- None.

### Removed
- None.

### Fixed
- None.

### Security
- None.

## [1.0.0] - 2024-04-23

### Added
- Initial release of the project.
- Implemented functionality for core features.
- Created project documentation using material mkdocs.

### Changed
- None.

### Deprecated
- None.

### Removed
- None.

### Fixed
- None.

### Security
- None.
