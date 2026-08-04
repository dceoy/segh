# GitHub REST client evaluation

## Decision

Reject `github.com/google/go-github/v89` at `v89.0.0` for the current
`segh` REST transport.

The library provides request construction, bearer authentication, API-version
headers, Enterprise URL configuration, and typed HTTP/rate-limit errors. A
parity-oriented adapter must still retain `segh`'s strict `GH_HOST` mapping,
bounded response decoding, retry and backoff policy, cancellable waits,
bearer-token redaction, and availability classification. The measured candidate
increases maintained code and cyclomatic complexity and does not preserve the
retained 64 KiB error-body materialization bound.

No candidate dependency, adapter, feature flag, or dual-client path remains in
the final tree.

## Reduced-main measurement snapshots

The implementation-order prerequisite is complete: the #57 PR-security removal
and #58 source-scan controller reduction are both present in the measured
baseline.

- Reduced `main` baseline: `1d57fcaf9300fe6afb26ac909f1ff768d7caa14d`.
- Parity-complete candidate: `f713da854373fa8183b93134aa662b8c313f0e1b`.
- Restored retained implementation: `32acece1486843e48d340a74e975e1f7ac8f5ab1`.
- Candidate standard CI/CD: run `30940419324` (`CI/CD` run 164), passed.
- Candidate measurement: run `30940420032`
  (`Issue 59 candidate verification` run 10), passed.
- Retained standard CI/CD: run `30940593612` (`CI/CD` run 168), passed.
- Retained measurement: run `30940593651`
  (`Issue 59 candidate verification` run 14), passed.

The candidate and restored-retained snapshots contain the same 323-line
`client_parity_test.go` suite and ran the complete reduced repository test
corpus. After the rejection was confirmed, the final tree removed that broad
measurement harness and retained only 154 lines of previously missing
production-contract checks in `client_contract_test.go`. Existing retry,
terminal-response, server-redaction, and cancellation coverage remains in
`client_test.go` rather than being duplicated.

## Measured adoption gate

All directly associated tests were identical in the two measurement snapshots.

| Scope | Retained | Candidate | Delta |
| --- | ---: | ---: | ---: |
| `internal/github/client.go` | 280 | 318 | +38 |
| `internal/github/client_test.go` | 355 | 355 | 0 |
| `internal/github/test_client_test.go` | 56 | 56 | 0 |
| `internal/github/client_parity_test.go` | 323 | 323 | 0 |
| Production plus directly associated tests | 1,014 | 1,052 | +38 |

Cyclomatic complexity was measured on `internal/github/client.go` with
`github.com/fzipp/gocyclo/cmd/gocyclo@v0.6.0`.

| Metric | Retained | Candidate | Delta |
| --- | ---: | ---: | ---: |
| Function complexity sum | 72 | 80 | +8 |
| Maximum function complexity | 12 | 12 | 0 |
| Functions measured | 15 | 16 | +1 |

The candidate misses the target reduction of at least 200 maintained lines by
238 lines and is harder, not easier, to audit by aggregate complexity.

The final retained tree removes the temporary parity harness:

| Final retained scope | Lines |
| --- | ---: |
| `internal/github/client.go` | 280 |
| `internal/github/client_test.go` | 355 |
| `internal/github/test_client_test.go` | 56 |
| `internal/github/client_contract_test.go` | 154 |
| Production plus directly associated tests | 845 |

The measurement workflow executed the same commands for both snapshots:

```text
go mod tidy
gofmt check for client.go and all three directly associated test files
go vet ./...
go test ./...
go test -race ./...
go build -trimpath ./cmd/segh
wc -l internal/github/client.go \
  internal/github/client_test.go \
  internal/github/test_client_test.go \
  internal/github/client_parity_test.go
go run github.com/fzipp/gocyclo/cmd/gocyclo@v0.6.0 \
  internal/github/client.go
```

The ordinary CI/CD workflow additionally passed configuration validation,
coverage-enabled race tests, `golangci-lint`, `actionlint`, and the production
build for both snapshots.

## Caller and endpoint inventory

All requests are read-only `GET` operations.

| Caller | Endpoint |
| --- | --- |
| Installation coverage | `/orgs/{org}/installations` |
| Installation coverage | `/installation/repositories` |
| Repository inventory | `/orgs/{org}/repos` |
| Actions policy | `/repos/{owner}/{repo}/actions/permissions` |
| Actions policy | `/repos/{owner}/{repo}/actions/permissions/workflow` |
| Actions policy | `/repos/{owner}/{repo}/actions/permissions/fork-pr-contributor-approval` |
| Rulesets | `/repos/{owner}/{repo}/rules/branches/{branch}` |
| Classic protection | `/repos/{owner}/{repo}/branches/{branch}/protection` |
| Dependency graph | `/repos/{owner}/{repo}/dependency-graph/sbom` |
| Dependabot alerts | `/repos/{owner}/{repo}/vulnerability-alerts` |
| Dependabot updates | `/repos/{owner}/{repo}/automated-security-fixes` |
| Security policy | `/repos/{owner}/{repo}/community/profile` |
| Security policy and manifests | `/repos/{owner}/{repo}/contents/{path}` |
| Lock-file inventory | `/repos/{owner}/{repo}/git/trees/{branch}` |
| Source-scan planning | `/repos/{owner}/{repo}/commits/{branch}` |

Repository and installation enumeration use deterministic 100-item pages.
Repository output is sorted after concurrent enrichment. The source-scan matrix
is independently bounded to 256 immutable targets. Each decoded API response is
bounded to 64 MiB and current error materialization is bounded to 64 KiB.
Overall pagination is bounded by the caller context deadline.

## Retained transport contract

- `GH_TOKEN` is mandatory and is the only credential source.
- `GH_HOST` defaults to `github.com` and accepts only a hostname, optionally
  with a port.
- `github.com` maps to `api.github.com`.
- GHE.com data-residency hosts map to `api.<tenant>.ghe.com`.
- Other hosts map to the GHES `/api/v3` base path.
- IPv6 literals and custom HTTPS ports are supported.
- Redirects are not followed.
- Requests carry `Authorization: Bearer`, `User-Agent: segh`,
  `Accept: application/vnd.github+json`, and
  `X-GitHub-Api-Version: 2022-11-28`.
- Successful decoded bodies are bounded before `json.Unmarshal`.
- Status-only probes stream to `io.Discard` without retaining the body.
- Transport failures, body-read failures, and malformed JSON are retryable.
- 408, 429, transient 5xx, primary rate limits, and secondary rate limits are
  retried at most four attempts.
- Ordinary retries use delays of 1, 2, and 4 seconds.
- Rate-limit retries use at least one minute and honor `Retry-After` or reset
  time; caller cancellation terminates a wait.
- 401, ordinary 403, 404, and 422 are terminal.
- 404, 410, and 501 map to `unsupported`; other unavailable evidence maps to
  `unknown`.
- Token values are removed from server, transport, and decode diagnostics;
  messages are trimmed and capped at 512 bytes.

Inventory separately promotes any 401/403 observed during per-repository
collection into the authentication/permission failure path. Endpoint-specific
404 handling and source-scan 404/422 classification remain caller-owned.

## Candidate responsibility analysis

The candidate used `go-github.NewClient`, `NewRequest`, and `BareDo`. It
delegated bearer-header injection, request construction, API-version headers,
and typed HTTP/rate-limit error parsing. The adapter still retained:

- strict `GH_HOST` parsing and GitHub.com/GHE.com/GHES URL mapping;
- redirect rejection through the injected production `http.Client`;
- four-attempt retry classification and 1/2/4-second backoff;
- rate-limit floor and server-hint waits;
- cancellation during requests and custom waits;
- bounded successful-response reads and explicit JSON decoding;
- malformed-response retries;
- token sanitization and 512-byte diagnostics;
- `APIError` and `ErrorState` mappings used by inventory and planning; and
- all caller pagination, ordering, and target bounds.

The library's proactive internal rate-limit state was disabled so that it could
not introduce a second clock or waiting policy outside the injected `segh`
wait function.

The candidate did not preserve the retained 64 KiB error-body materialization
bound: `go-github` reads up to 1 MiB before the adapter receives the typed error.
Restoring the exact bound requires another transport/body layer. This is an
explicit behavior-parity failure in addition to the failed size and complexity
gates.

## Fixture results

The complete API, inventory, policy, content, ruleset, dependency, lock-file,
and integrated source-scan planning/reconciliation corpus ran against both
reduced-main measurement snapshots.

| Fixture group | Candidate | Retained |
| --- | --- | --- |
| GitHub.com, GHE.com, GHES, custom port, IPv6, malformed host | Pass | Pass |
| Authentication, API-version, accept, and user-agent headers | Pass | Pass |
| Production-constructor redirect rejection | Pass | Pass |
| Cancellation, timeout, transport/read/decode failures | Pass | Pass |
| 408, 429, representative 5xx, primary/secondary rate limits | Pass | Pass |
| Exact four-attempt ceiling and 1/2/4-second backoff | Pass | Pass |
| Repeated rate-limit floor and server-hint delays | Pass | Pass |
| 401, ordinary 403, 404, and 422 terminal classification | Pass | Pass |
| Successful response bound, empty body, malformed JSON | Pass | Pass |
| Token redaction from server and transport diagnostics | Pass | Pass |
| Pagination, inventory identity, policy, and source-scan semantics | Pass | Pass |
| Retained 64 KiB error-body materialization bound | Not preserved | Pass |

## Dependency and security assessment

The candidate added direct `github.com/google/go-github/v89 v89.0.0`, indirect
`github.com/google/go-querystring v1.2.0`, and the module checksum surface for
`github.com/google/go-cmp`. The library requires Go 1.25. It introduces no
implicit credential discovery, telemetry, persistent cache, daemon, background
goroutine, or unrelated runtime network request.

Those properties do not offset a 38-line increase, an 8-point aggregate
complexity increase, and the error-body-bound mismatch.

## Conclusion

The measured replacement fails the adoption gate. Retaining the current
standard-library transport is smaller, less complex, and preserves the stricter
resource bound. The final tree keeps only focused regression coverage for
production guarantees that were previously untested; the broad parity harness
remains available only in the reproducible measurement snapshots.
