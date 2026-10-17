# Ecosystem audit: OptiRadar checkpoint

Branch `claude/project-thread-0cf20u`. Updated per batch. Status: CONFIRMED / ALREADY_FIXED / NOT_REPRODUCIBLE /
FIXED_AND_TESTED / BLOCKED. Design and rollout: `docs/governance.md`.

| Id | Finding | Status | Evidence | Tests | Remaining |
|---|---|---|---|---|---|
| A02 | Radar has no machine-readable permission catalog | FIXED_AND_TESTED | `governance/Catalog.java`, `ManifestExporter.java`, `docs/governance/optiradar-manifest.json` (v2.0, 8 modules, 22 features, 34 permissions, explicit `delegable`) | `CatalogTest` (6) | Nexus import dry-run NOT_RUN |
| R02 | Radar decides access with native flags, not Nexus | FIXED_AND_TESTED | `GovernanceService.require:235` (grants via effective-permissions + commercial-context), cache <= 300 s, fail closed, no fallback | `GovernanceServiceTest` (53) | none |
| R05 | Entry points other than REST are unguarded | FIXED_AND_TESTED | REST `GovernanceRequestFilter.filter:69` + `@Governed` on every resource; WebSocket `AsyncSocketServlet:90-98`, `AsyncSocket` re-check; `MediaFilter:83`; `NotificationManager`; `TaskReports`; reports/exports split view/export | `GovernanceRequestFilterTest`, `GovernanceCoverageTest`, `GovernanceGuardTest` | `AsyncSocket` re-check has no unit test (verified by reading only) |
| R05b | Tenant user escalates through native objects | FIXED_AND_TESTED | `GovernanceGuard` (tenant attribute, reserved user attributes, placement, notification+command); `OpenIdProvider` ignores admin claim when governed | `GovernanceGuardTest` | none |
| R05c | Startup depends on the identity provider | FIXED_AND_TESTED | `OpenIdProvider` lazy, retrying discovery; governance does no I/O at start | `OpenIdProviderTest` (27 with Catalog) | none |
| R08/A25 | Delegation of users and roles | FIXED_AND_TESTED (server) | `governance/DelegationService.java`, `api/resource/AccessResource.java` (`/api/access/*`, `optiradar.access.manage`), audit `LogAction.delegation` | `DelegationServiceTest` (25), `AccessResourceTest` (5) | web pages: see optiradar-web status |
| A29/R06 | Product switcher | FIXED_AND_TESTED (server) | `GovernanceService.products`, `ProductContext`, `GovernanceResource.products` (`/api/governance/products`), `OpenIdProvider.createAuthUri(.., tenantHint)` + `validTenantHint`, `SessionResource.openIdAuth` | `ProductSwitcherTest` (23), `ProductContextTest` (7), `GovernanceResourceProductsTest` (4), `OpenIdProviderTest` (+2) | web switcher: see optiradar-web status |
| A10 | Telematics scope | FIXED_AND_TESTED (Radar side); gateway gaps open | `docs/telematics.md` (inventory, T1-T8, scope matrix), `telematics/TelematicsSnapshot.java`, `api/resource/TelematicsResource.java` (`/api/telematics/v1/latest`, schema 1.0, additive), `database/DeviceTenants.java`, key `telematics.staleSeconds` | `TelematicsSnapshotTest` (20), `TelematicsResourceTest` (4), `DeviceTenantsTest` (4), `GovernanceCoverageTest` | OptiNexus gateway: T1 duplicate drop on fix time, units/time fields, connector switch; owner decisions D-T1..D-T3 |
| A12/A15 | Web error handling and bundle | CONFIRMED | optiradar-web, see its own status file | - | batch R5 |

## Commands run (this repo)

* Tests: `bash /tmp/claude-0/radar-test.sh`-style scratch build (`rt.sh`), `--select-package org.traccar.governance`:
  178 tests, 0 failed. Whole scratch suite `--scan-classpath`: 800 passed, 0 failed, 26 skipped, 1 aborted (assumption).
* Style: `gradle checkstyleMain checkstyleTest -x compileJava -x compileTestJava` in `/tmp/claude-0/cs`: clean.
* NOT_RUN: Gradle `./gradlew test` of the repository itself (the sandbox has no network for the build plugins; the scratch
  build compiles the same sources with the same test classpath), live run against a real OptiNexus (contract is covered
  by `FakeNexus`, built from the documented JSON and the Nexus controllers).

## Decisions taken

* Native administrator = OPERATOR (break-glass), never a tenant user; tenant users cannot manage users, impersonate or
  read `/permissions`. Per-user device narrowing stays an operator task via native links.
* Scheduled-report occurrences skipped while the recipient lacks `reports.schedule` are not replayed.
* The telematics connector's token user is not Nexus-linked: listed in `governance.integrationUsers`, GET devices,
  groups and latest positions only.
* Delegable set: see `docs/governance.md` (26 delegable, 8 not). OWNER DECISION: whether data-exit permissions
  (`reports.export`, `reports.schedule`, `positions.export`) and `stream.view` should stay delegable.

## Nexus contract notes

* `effective-permissions` and `commercial-context` need scopes `authorization.check` and `commercial.read` on the
  Radar service account (token per scope).
* No gap needing a Nexus change so far.
