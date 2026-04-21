<!--
Sync Impact Report
===================
Version change: 0.0.0 → 1.0.0
Modified principles: N/A (initial constitution)
Added sections:
  - Core Principles (4 principles)
  - Performance Requirements
  - Development Workflow
  - Governance
Removed sections: None
Templates requiring updates:
  - .specify/templates/plan-template.md — ✅ no update needed (generic gates)
  - .specify/templates/spec-template.md — ✅ no update needed (generic structure)
  - .specify/templates/tasks-template.md — ✅ no update needed (generic phases)
Follow-up TODOs: None
-->

# HAProxy SPOA Hub Plugin SSO Auth Constitution

## Core Principles

### I. Code Quality

All code MUST be clear, maintainable, and self-documenting.

- Functions MUST have a single responsibility and MUST NOT exceed
  a complexity that hinders readability.
- Public APIs MUST be documented with purpose, parameters, return
  values, and error conditions.
- All warnings from the project's linter and static analysis
  tooling MUST be resolved before merge.
- Dead code, unused imports, and unreachable branches MUST be
  removed immediately upon discovery.
- Naming MUST accurately reflect purpose — rename when meaning
  drifts after refactoring.
- DRY: duplicated logic MUST be extracted into shared functions
  when the same pattern appears more than twice.

### II. Testing Standards

Every behavioral change MUST be verified by automated tests.

- Bug fixes MUST include a regression test that fails before the
  fix and passes after.
- New features MUST have tests covering the primary success path
  and at least one failure/edge-case path.
- Tests MUST be deterministic — no reliance on external services,
  wall-clock time, or ordering side effects.
- Integration tests that exercise HAProxy SPOA protocol
  interactions MUST use reproducible fixtures or controlled
  test harnesses rather than live infrastructure.
- Test names MUST describe the scenario under test, not the
  implementation detail being exercised.
- Coverage regressions MUST be justified in the PR description
  when unavoidable.

### III. User Experience Consistency

The plugin MUST present a predictable and coherent interface to
HAProxy operators and end users of SSO-protected services.

- Configuration options MUST follow HAProxy naming conventions
  and MUST be documented with defaults, valid ranges, and
  examples.
- Error messages returned to HAProxy MUST be actionable: they
  MUST identify what failed and suggest a remediation path.
- Authentication flows MUST degrade gracefully — a downstream
  identity provider outage MUST NOT crash the SPOA agent or
  leave HAProxy connections hanging.
- Behavioral changes to existing configuration directives MUST
  be treated as breaking changes and versioned accordingly.
- Log output MUST use structured formats and consistent severity
  levels so operators can integrate with existing observability
  stacks.

### IV. Performance Requirements

The plugin MUST NOT become a bottleneck in the HAProxy request
processing pipeline.

- SPOA message processing latency MUST remain below 5 ms at p99
  under normal operating conditions.
- Memory allocations in the hot path MUST be minimized; prefer
  pre-allocated buffers and object pooling where applicable.
- The plugin MUST support concurrent SPOA connections without
  lock contention degrading throughput.
- Token validation and session cache lookups MUST be bounded in
  time — network calls to identity providers MUST enforce
  timeouts and circuit-breaker patterns.
- Performance-sensitive changes MUST include benchmark results
  in the PR description demonstrating no regression.

## Performance Requirements

Quantitative targets for the SPOA authentication path:

| Metric | Target | Measurement |
|--------|--------|-------------|
| p99 latency (auth check) | < 5 ms | Benchmark suite |
| p50 latency (auth check) | < 1 ms | Benchmark suite |
| Max memory per connection | < 4 KB | Profiler |
| Concurrent connections | ≥ 10 000 | Load test |
| Startup time | < 500 ms | Wall clock |

These targets MUST be validated by the benchmark suite before
each release. Regressions MUST block the release until resolved
or an exception is documented and approved.

## Development Workflow

All changes follow this process:

1. **Branch**: Create a feature branch from `main`.
2. **Test first**: Write or update tests that capture the
   intended behavior change before modifying production code.
3. **Implement**: Make the minimal change that satisfies the
   tests and the specification.
4. **Lint and test**: All linters and the full test suite MUST
   pass locally before pushing.
5. **Benchmark**: If the change touches the SPOA hot path, run
   benchmarks and include results in the PR.
6. **Review**: Every PR MUST be reviewed by at least one other
   contributor before merge.
7. **CI gate**: The CI pipeline MUST pass — no manual overrides
   of failing checks.

## Governance

This constitution is the authoritative source of project
principles. In case of conflict between this document and any
other project artifact, this document prevails.

- **Amendments** MUST be proposed as a PR modifying this file,
  reviewed, and approved before merge.
- **Versioning** follows semantic versioning:
  - MAJOR: principle removed or fundamentally redefined.
  - MINOR: new principle or section added, or material expansion
    of existing guidance.
  - PATCH: wording clarification, typo fix, non-semantic change.
- **Compliance review**: each PR review MUST verify adherence to
  the principles defined above. Deviations MUST be justified in
  the PR description and approved by a reviewer.

**Version**: 1.0.0 | **Ratified**: 2026-04-12 | **Last Amended**: 2026-04-12
