# Central governance: OptiNexus decides what a tenant user may do in OptiRadar

With `governance.enable` on, OptiNexus is the only authority for **who may do what** in OptiRadar. OptiRadar keeps
only the tracking data (devices, positions, events) and decides nothing about people by itself. Off (the default),
OptiRadar behaves exactly as before. Code: `org.traccar.governance`.

## The model in one page

| Question | Answered by | Where |
|---|---|---|
| Who is this person and which tenant? | the OpenID identity `(issuer, sub)` and the tenant group link | `GovernanceService.principal` |
| What may they do? | `POST /api/v1/authorization/effective-permissions` (schema 1.0, scope `authorization.check`) | `GovernanceService` |
| Did the tenant buy it? | `GET /api/v1/tenants/{id}/commercial-context` (scope `commercial.read`): tenant ACTIVE, application enabled, capability on, module not off | `GovernanceService` |
| Which devices? | native device/group links of the tenant (they can only **restrict**) | Traccar permission model |

Effective access = tenant active **and** application entitled **and** feature entitled **and** user active **and**
permission granted **and** device/group scope. Any "no" is a no.

### Account kinds (`GovernedPrincipal`)

* **CENTRAL**: an OpenID-linked account that reaches exactly one tenant (its group, or a group below it, carries
  `optinexusTenantId`). All it may do comes from OptiNexus.
* **OPERATOR**: a native administrator and the server's service account. The break-glass and installation role. Exempt
  from tenant grants, never created from OpenID, and logged at INFO (once per 10 minutes per account).
* **INTEGRATION**: a local read-only account listed in `governance.integrationUsers` (the OptiNexus telematics connector
  token user). It may `GET` devices, groups and the latest positions and nothing else.
* **DENIED**: everything else (password users, accounts with no or several tenants, a subject that is not an OptiNexus
  id). Refused with `governance_identity_required` or `governance_tenant_unresolved`.

## Freshness, outage and fail-closed rules

* Grants and entitlements are cached for **at most 300 s** (`governance.ttl` is clamped to 1..300; a shorter
  `ttl_seconds` from OptiNexus wins). A denial is cached 30 s.
* After the lifetime ends OptiRadar asks again. If OptiNexus cannot answer (network, timeout, 5xx, 429/408, a token that
  is refused, an answer about another user/tenant, an unknown schema, an answer that is not the documented envelope) the
  request is **refused with 503 `governance_unavailable` and `Retry-After`**. There is **no local fallback, no stale
  grant after expiry, nothing is widened**. An outage never logs anybody out and never ends sessions.
* While OptiNexus is down, further requests fail fast for the `Retry-After` window (1..120 s), so a dead OptiNexus does not
  stack up threads. Only one question per user/tenant is in flight at a time (single flight).
* OptiNexus ending a person's access (`USER_NOT_ACTIVE`, `USER_NOT_FOUND`, `TENANT_NOT_ACTIVE`, `TENANT_NOT_FOUND`,
  `APPLICATION_NOT_ACTIVE`) answers 401 `governance_access_revoked`, ends the user's sessions (rate limited) and drops the
  cached grants. Any other denial is a 403 and keeps the session.
* **Startup never depends on OptiNexus.** OpenID discovery is lazy and retried (10 s window), the governance layer does no
  network I/O when it starts, and a missing OptiNexus configuration only logs an error and refuses tenant users.
* OptiRadar runs standalone (governance off): nothing here is reached, no OptiFleet or OptiEntry is needed.

## Where it is enforced

| Entry point | How |
|---|---|
| REST `/api/*` | `GovernanceRequestFilter` (after authentication) reads `@Governed` on the resource. A route without an answer is refused (`governance_route_unmapped`) and `GovernanceCoverageTest` fails the build. |
| Reports and exports | `REPORTS_VIEW` for JSON, `REPORTS_EXPORT` for every `*Excel`/e-mail route, `REPORTS_SCHEDULE` for scheduled reports; positions export `POSITIONS_EXPORT`. |
| Commands | `COMMANDS_SEND` on send; a notification that sends a command also needs it (`GovernanceGuard`). |
| WebSocket `/api/socket` | needs `LIVE_VIEW` at connect; every 30 s the socket is re-checked off-thread and closed with 1008 (denied), 1013 (unavailable) or 1011; event frames need `EVENTS_VIEW`, log frames are operator-only. |
| Media files | `MediaFilter` needs `POSITIONS_VIEW`. |
| Notifications (server push) | `NotificationManager` delivers to a user only while they hold `EVENTS_VIEW`. |
| Scheduled reports | `TaskReports` skips a recipient that no longer holds `REPORTS_SCHEDULE`. A skipped occurrence is **not** replayed (decision: a report a person may no longer receive must not be sent late). |
| MCP | the MCP tools call the same REST routes, so the same filter applies. |

Tenant isolation is unchanged and still the first line: tenants stay separated by the group link; governance can only
narrow. `GovernanceGuard` additionally refuses a tenant user who tries to set or change the `optinexusTenantId`
attribute of a group, to place a device or group at the top level (where no tenant owns it), or to change the
sign-in-owned user attributes (`optinexusSessionsNotBefore`, `optinexusDeactivated`, `optinexusLogoutUrl`,
`optinexusApps`).

## Catalog and manifest

`Catalog` is the single source of truth: 8 modules, 22 features (capabilities) and 34 permissions (`optiradar.*`). The
Nexus manifest (version 2.0, revision in `Catalog.REVISION`) is generated from it:

* committed copy: `docs/governance/optiradar-manifest.json` (a test fails when it is stale);
* live: `GET /api/governance/manifest` (operator only) and `java -cp ... org.traccar.governance.ManifestExporter`.

Import it in OptiNexus as documented in `MANIFEST_IMPORT.md` (additive, never deletes).

### Which permissions are delegable (rationale)

`delegable = true` means a tenant's Admin Tenant may put the permission into a custom role for the tenant's own users. The
default is **false**; each `permission(...)` in `Catalog` states it, and `CatalogTest` holds the same explicit list, so a
change needs two deliberate edits.

* Delegable (26): everything that is looking at, or day-to-day operation of, the tenant's own fleet: live view,
  position history, devices and groups (view and manage), geofences, report viewing, report export and scheduling,
  position export, saved-command list, events, notification rules, drivers, maintenance, calendars, orders, computed
  attribute list, video view.
* **Not** delegable (8; a platform/safety/privacy decision, not a tenant admin's): `commands.send` (acts on a vehicle),
  `commands.manage` (defines what can be sent), `positions.delete` (destroys history), `devices.odometer.set` (changes
  evidence), `notifications.send` (announcements to every user), `sharing.manage` (public links),
  `attributes.manage` (computed expressions are evaluated by the server) and `access.manage` (delegating delegation).
* Whether `reports.export`/`reports.schedule`/`positions.export` (data leaving the system) and `stream.view` should be
  delegable is a business/privacy decision; they are delegable now and can be tightened by changing the flag and bumping
  `REVISION` (recorded in the status file as an owner decision).

## Access management: users and custom roles (R08/A25)

An Admin Tenant manages the users and custom roles of **their own tenant** from OptiRadar. OptiRadar stores nothing: each
call is forwarded to the OptiNexus delegation API with OptiRadar's service account (scope `tenant.delegate`, bound to the
`optiradar` application). Needs `governance.enable`, permission `optiradar.access.manage` (not delegable) and the tenant
entitlement `optiradar.access.users`. A native administrator or password user has no OptiNexus identity to act as and is
refused (`delegation_actor_required`).

| Route (`/api/access/...`) | OptiNexus (`/api/v1/delegation/tenants/{tenant}/...`) |
|---|---|
| `GET catalog` | `GET /catalog` delegable permissions and assignable roles |
| `GET users?search=&perPage=` | `GET /users` (paged, `meta.pagination`) |
| `POST users` `{email,name,initial_password?,role_ids?}` | `POST /users` (201 created, 200 linked/existing) |
| `PUT users/{user}/roles` `{role_ids}` | `PUT /users/{user}/roles` |
| `DELETE users/{user}` | `DELETE /users/{user}` |
| `POST roles` / `PUT roles/{role}` / `DELETE roles/{role}` | same on `/roles` |

* Requests and answers are OptiNexus' own documents (snake_case) wrapped as `{data, meta}`; **no `tenant_id` or
  `acting_user_id` is accepted from the caller** (such a field is a 422): the tenant and the acting user (the signed-in
  user's OptiNexus subject) come from the identity link. Unknown fields are refused, ids in the path must be UUIDs.
* OptiNexus verifies on every call that the actor is an active Admin Tenant with access to OptiRadar and decides which
  permissions are delegable (`PERMISSION_NOT_DELEGABLE` with the offending keys).
* Errors (`{error, message, nexusCode, details, correlationId}`): the OptiNexus code lower-cased with the prefix
  `delegation_` and its status (403/404/409/422; 400 becomes 422); `delegation_unavailable` (503, `Retry-After`) when
  OptiNexus does not answer within `governance.connectTimeout`/`readTimeout`; `delegation_misconfigured` (503) when the
  service account is not bound or lacks the scope (an operator problem, logged as an error);
  `delegation_unexpected` (502) for a status that is not in the contract.
* Every change is written to the audit trail (`GET /api/audit`, operator only) as action `delegation` with operation,
  target (an id or the e-mail/role name, never a password), outcome (`ok` or the refusal code) and the correlation id.
* After a change the grants cached for the affected user (or for the whole tenant when a role changes) are dropped, so
  the next request already sees the new access. OptiNexus queues the back-channel logout when a user is removed.

## Product switcher (A29/R06)

`GET /api/governance/products[?fresh=true]` (signed-in tenant user, no permission needed beyond access to OptiRadar) answers
`{governed, tenant:{id,code,name}, products:[{code,name,url,current}], expiresAt, ttlSeconds}` from OptiNexus
`POST /api/v1/authorization/product-context` (scope `authorization.check`; the body is only `user_id` and `tenant_id` of the
authenticated principal). What the browser gets is reduced by `ProductContext`:

* only products the tenant subscribes to and the user was assigned (OptiNexus decides); the governance portal (`cgo`) is
  dropped here as well, even if it were sent;
* `current` is decided by this server (`code == governance.applicationCode`), not by the answer;
* a product needs a code, a name and an absolute `http(s)` address without credentials; `javascript:`, `data:`,
  relative, credentialed or custom-scheme addresses are dropped; at most 20 products, duplicates dropped;
* every `url` is the launch address plus `tenant_hint=<tenant id>` (an existing hint is replaced, the fragment is
  dropped). No token, code or secret is ever added.

Freshness: cached per `tenant|subject` for at most `min(ttl_seconds, governance.ttl, 300)`; `fresh=true` asks OptiNexus
again but at most once every 5 seconds per user (a busy switcher cannot flood OptiNexus); concurrent renders share one
question. The web app asks fresh when the switcher opens and again before it leaves for another product.

Failure: OptiNexus down, a refused service account, a malformed answer or an answer about another user, tenant or
application gives `503 governance_unavailable` and no products (nothing is cached, `Retry-After` is kept). An outage never
ends a session. `allowed=false` (any `deny_reason`) means OptiNexus ended the access: the user's cached grants and products
are dropped, the user's sessions end (`OpenIdLifecycle`), the browser session is invalidated and the answer is
`401 governance_access_revoked`. Operators (native administrators) get an empty list; accounts without OptiNexus grants get
`403`.

Target side (when OptiRadar is the product being opened): `GET /api/session/openid/auth?tenant_hint=<value>` forwards
`tenant_hint` to OptiNexus `/oidc/authorize` only when it is a tenant id (UUID) or a tenant code
(`[A-Za-z0-9][A-Za-z0-9._-]{0,63}`); anything else is silently dropped, never repaired. State, nonce and PKCE are created
by the server as before; the hint never changes them. OptiRadar accepts no other target: there is no `next`/`return_to`
parameter, and `redirect_uri` is only honoured for the mobile scheme when `openid.allowMobileRedirect` is on.

## Native flags in Nexus mode (what happens to Traccar's `administrator`, `readonly`, `disabled`, limits)

| Native flag | Governed + OpenID-linked tenant user | Local account (operator) |
|---|---|---|
| `administrator` | A tenant user is never an administrator: the `openid.adminGroup` claim is ignored and native administrators are refused at tenant sign-in. A native administrator is an OPERATOR. | full power, logged |
| `readonly` | still applies (only restricts: no writes even if OptiNexus granted them) | applies |
| `disabled`, `expirationTime`, `deviceLimit`, `userLimit` | still apply (only restrict) | apply |
| `fixedEmail`, `poi`, map prefs | cosmetic, unchanged | unchanged |
| device/group links | the tenant boundary and per-user narrowing, operator-managed | unchanged |

Tenant users cannot list or create users, impersonate (`/session/{id}`), list `/permissions`, or use the OIDC-IdP
endpoints. User management for a tenant is done through OptiNexus delegation (see the access-management section).

## Configuration keys

| Key | Default | Meaning |
|---|---|---|
| `governance.enable` | false | turn central governance on |
| `governance.applicationCode` | optiradar | application code in OptiNexus (permission keys start with it) |
| `governance.ttl` | 300 | longest cache time in seconds (clamped to 300) |
| `governance.connectTimeout` / `governance.readTimeout` | 2000 / 4000 | ms to wait for OptiNexus |
| `governance.integrationUsers` | - | comma-separated emails or logins of read-only machine accounts |
| `optinexus.baseUrl/clientId/clientSecret` | - | OptiRadar's service account (scopes `authorization.check`, `commercial.read`; `tenant.delegate` for access management) |
| `openid.tenantClaim` | - | required: a governed tenant user must be tied to a tenant |

## Rollout

1. In OptiNexus: create the OptiRadar application and its service account (scopes above), import the manifest.
2. Set the keys, keep `governance.enable=false`, deploy, and check `GET /api/governance/context` as a signed-in user
   (`governed:false` while off).
3. Make sure the telematics connector's token user is read-only and listed in `governance.integrationUsers`.
4. Turn `governance.enable` on and restart. Watch the log for `governance_unavailable` (OptiNexus reachability) and
   `Route ... has no @Governed answer`.
5. Rollback: set `governance.enable=false` and restart. Nothing is migrated.

## Error body

Every governance refusal is JSON: `{ "error": "<code>", "message": "...", "permission": "...", "correlationId": "..." }`
with `X-Correlation-Id`, `Cache-Control: no-store` and, for 503, `Retry-After`. Codes: `governance_access_revoked` (401),
`governance_permission_denied`, `governance_not_entitled`, `governance_operator_only`, `governance_identity_required`,
`governance_tenant_unresolved`, `governance_route_unmapped`, `governance_reserved_attribute` (403),
`governance_invalid_placement` (400), `governance_unavailable` (503). A caller may send its own `X-Correlation-Id`
(8-64 chars of `A-Za-z0-9._-`); it is echoed and logged.
