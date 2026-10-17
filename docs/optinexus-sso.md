# Single sign-on with OptiNexus

OptiRadar signs users in through OptiNexus (OpenID Connect) with its built-in OpenID client (inherited from Traccar). Two settings,
`openid.tenantClaim` and `openid.tenantGroupAttribute`, tie each login to a tenant. Without `openid.tenantClaim`
nothing below changes and OpenID behaves as in upstream Traccar.

## How a login works

1. The user opens `https://<radar>/api/session/openid/auth` (this is the application's launch URL in OptiNexus), or
   uses "Login with OpenID" on the login page. OptiNexus signs them in, or reuses the session they already have from
   OptiFleet, and sends them back to `/api/session/openid/callback`.
2. OptiNexus only issues the login if the user's organization is subscribed to OptiRadar and the user has been given
   access to it. Otherwise the callback is refused: no session is created and the browser returns to the login page
   with a generic "sign-in failed" message (the reason is only in the server log).
3. With `openid.tenantClaim` set, OptiRadar then:
   * requires the claim named by `openid.tenantClaim` (OptiNexus: `tenant_id`) and a verified email;
   * looks for **one** group whose attribute `openid.tenantGroupAttribute` equals that tenant id; no group, or more
     than one, rejects the login before any account is created or changed;
   * links the user to that group and removes links to any other tenant group, so a user who works for several
     tenants only sees the tenant they signed in to. Groups and links that carry no tenant attribute are left alone;
   * stores the applications OptiNexus lists for the user (claim `apps`) in the user attribute `optinexusApps`, which
     the web app shows as links in the account menu. Only http(s) addresses are kept.

Devices belong to a tenant through their group (devices in a tenant group, or in its sub-groups, are visible to the
tenant's users).

## How the login is protected

* **State, nonce and PKCE.** Every sign-in is started by the server (`/api/session/openid/auth`). It creates a
  one-time `state`, a `nonce` and an S256 PKCE verifier, keeps them in server memory, bound to the browser session
  that started it, and sends only the state, nonce and PKCE challenge to OptiNexus. A callback is accepted only with
  the state of a sign-in that is still pending, in the same browser, within 10 minutes; a state is used up the first
  time it is presented, whatever the outcome (replay, expiry, another browser and unknown states are refused). At most
  5 sign-ins are pending per browser and 5000 overall. The pending logins live in the memory of the server process
  (like its web sessions), so run one OptiRadar instance or pin a user to one instance.
* **ID token.** The ID token returned for the code is verified completely: signature against the OptiNexus key set
  (selected by `kid`; an unknown `kid` refreshes the keys, so a rotation is followed), an allow-list of signature
  algorithms (`openid.idTokenAlgorithms`, default `RS256`; `none` and HMAC are refused), issuer, audience (and
  authorized party when there are several audiences), expiry, issue time and the nonce of this sign-in. The subject
  reported by the user info endpoint must be the subject of the ID token. An `iss` parameter on the callback must be
  the configured issuer.
* **Client registration.** Register the OptiRadar client in OptiNexus as a confidential client with
  `require_pkce = true` (OptiNexus then refuses a code request without S256 PKCE) and the exact redirect URI
  `https://<radar>/api/session/openid/callback`. `require_pkce = false` is not a supported setting.
* **Mobile app redirect** (`org.traccar.manager://…`) is refused unless `openid.allowMobileRedirect=true`. When it is
  on, the redirect address must be named when the sign-in starts (`/api/session/openid/auth?redirect_uri=…`), is
  fixed for that sign-in, and the state is still server-created and one-time, but it cannot be bound to a browser
  session. Leave it off unless the mobile app needs it, and register that redirect in OptiNexus as well.

## Who the user is: the OpenID identity, not the email

An OptiRadar account is tied to the identity the provider vouches for: the pair (issuer, subject), stored in
`tc_openid_identities` (unique per (issuer, subject) and per (account, issuer), enforced by the database). The email
is only a profile attribute.

* A known identity always signs in to the account it is linked to. If the provider reports a new email, it is copied
  into the account (unless another account already has that address, then it is kept and a warning is logged).
* **First sign-in of an existing account.** If the identity is unknown, the email is verified and an OptiRadar account
  with that email exists, the identity is linked to it **once** (`linkedvia = legacy-email`, audited in the action
  log). An account that is already linked to a different identity of the same provider is never handed over: the
  sign-in is refused and audited (this is what happens when an address is reused by another person). Set
  `openid.legacyEmailLinking=false` once the accounts of your users are linked to stop all linking by email.
* **No account yet:** one is created (only if registration allows) and linked (`new-account`). An unverified email never
  links or creates an account.
* **Back-channel logout, deactivation and reactivation** find the account by the subject of the token, never by email.
  A token about an identity that is not linked to any account here changes nothing.
* Upgrading: the table is created by the normal database migration. Existing accounts get their link at their first
  SSO sign-in after the upgrade; until then a logout or revocation from OptiNexus cannot reach them (they have no
  stable identity yet), so ask users to sign in once, or end their sessions by other means.

### One active tenant per account

An OptiRadar account has one active tenant. Signing in to another tenant (the same person, another organization)
moves the account to that tenant: links to groups and devices of other tenants are removed (including direct device
permissions, the account's own sub-group links and devices in other tenants' groups), and **every web session of the
account that began earlier ends** (the user sees the login page there), so no open session silently continues with a
different tenant's scope. Parallel sessions for two tenants at the same time would need the tenant to be part of the
session and of every permission check; this is a contract change that is not made here. Long-lived API tokens belong to
the account and are not ended by a tenant switch (a deactivation does end them). Groups and devices that belong to no
tenant are left alone.

### Opening OptiRadar from another product (tenant hint)

The product switchers of the other applications link to the launch URL plus `?tenant_hint=<tenant id>`. Both entry
points accept it: `/api/session/openid/auth?tenant_hint=…` forwards it to `/oidc/authorize`, and the web app (when the
launch URL is the web address) starts the same sign-in with the hint once, if the browser has no session. The hint is
used only when it is a tenant id (UUID) or a tenant code; anything else is dropped. OptiNexus continues in that tenant
using the existing single sign-on session, so no credentials are asked again. See `docs/governance.md` (Product switcher).

## Configuration (`conf/optiradar.xml`)

```xml
<entry key='openid.clientId'>optiradar</entry>
<entry key='openid.clientSecret'>…</entry>
<entry key='openid.issuerUrl'>https://nexus.example.com</entry>
<entry key='openid.allowGroup'>optiradar</entry>   <!-- OptiNexus "groups" claim lists application codes -->
<entry key='openid.tenantClaim'>tenant_id</entry>
<entry key='openid.tenantGroupAttribute'>optinexusTenantId</entry>   <!-- default -->
<entry key='openid.allowRegistration'>true</entry>  <!-- create the account on first SSO login -->
```

* Without `openid.issuerUrl` (no discovery) state the issuer and the key set yourself:
  `openid.issuer` (the `iss` of the ID tokens) and `openid.jwksUrl`; without them the server refuses to start OpenID
  rather than accept an ID token it cannot verify.
* Register OptiRadar as an OIDC client in OptiNexus (confidential, `require_pkce = true`) with the redirect URI
  `https://<radar>/api/session/openid/callback`, and set the application's launch URL to
  `https://<radar>/api/session/openid/auth` so "open OptiRadar" from OptiFleet signs in without a login screen.
* `openid.allowRegistration=false` (the default) rejects people who have no OptiRadar account yet. With `true`, the
  account is created on the first SSO login (only when the tenant has a group), so nobody has to be added by hand.
  Pair it with `users.defaultDeviceLimit=0`: new accounts then cannot create devices of their own and only see the
  devices of their tenant group. The limit blocks *adding* devices only; devices that come through the group stay
  visible. It is applied when an account is created, so it does not change accounts that already exist.
* `setup/optiradar-optinexus.xml` is a ready-to-copy sample with these settings. The default `setup/optiradar.xml`
  has none of them, so a plain installation behaves as before. With Docker (`CONFIG_USE_ENVIRONMENT_VARIABLES: "true"`) use
  `OPENID_CLIENT_ID`, `OPENID_TENANT_CLAIM`, `OPENID_ALLOW_REGISTRATION=true` and `USERS_DEFAULT_DEVICE_LIMIT=0`.

## Who may do what: central governance

Signing in proves who the person is. What they may do is decided by OptiNexus when `governance.enable` is on: permissions,
tenant entitlements, a five-minute freshness limit and a refusal (never a local fallback) when OptiNexus cannot answer.
Everything is in [governance.md](governance.md).

## Password sign-in keeps working

The integration only adds a way in. Users that have a password can still sign in on the login page with it, and a
deployment that does not set `openid.*` (or where OptiNexus is down) is unaffected. The one exception is deliberate:
an account that OptiNexus switched off (below) cannot sign in by password either, until OptiNexus lets the user in
again.

## Central logout and automatic deactivation

OptiNexus tells OptiRadar when a user's sessions have to end, through OpenID Connect Back-Channel Logout:

* Register `https://<radar>/api/session/openid/backchannel-logout` as the OIDC client's back-channel logout URI in
  OptiNexus (field `backchannel_logout_uri` of the OIDC client). The call carries a signed `logout+jwt` token; OptiRadar checks the signature
  against the OptiNexus keys, issuer, audience, age, and that each token is used once. Nothing else authorizes it.
* **Logout**: the user logged out in OptiNexus or in another application. Every OptiRadar session of that user ends,
  on all devices. The account stays active.
* **Access revoked**: the user was suspended or disabled, removed from the tenant, lost access to OptiRadar, or the
  tenant was suspended. Sessions end *and* the account is marked `disabled` with the attribute
  `optinexusDeactivated`, so password sign-in is refused as well. A revocation for one tenant only removes the user
  from that tenant's group (sessions still end); the account itself stays active.
* **Reactivation** happens at the next successful SSO login, and only for accounts that carry
  `optinexusDeactivated`. An account an administrator disabled by hand is never switched back on.
* Sessions started before the event are recognised by the user attribute `optinexusSessionsNotBefore`, so a
  restart or a second server instance does not bring them back.
* Logging out in the OptiRadar web app sends the user to the OptiNexus end-session URL (attribute
  `optinexusLogoutUrl`, set at SSO login), which logs them out of the other applications too and then returns to
  OptiRadar. Register the OptiRadar address (`https://<radar>`, as `web.url` / the server address, without a path)
  as a post-logout redirect URI of the OIDC client; without it OptiNexus shows its own "signed out" page.

Limits: a plain logout does not revoke long-lived OptiRadar API tokens (a deactivation does, because the account is
disabled). Web sessions and the live WebSocket connection check the same rules (account enabled, session not ended by
the provider) when they are opened.

## Events to OptiNexus

OptiRadar can report five kinds of events to OptiNexus (`POST /api/v1/events`, key prefix `optiradar.`):

| OptiRadar event | OptiNexus event |
|---|---|
| `deviceOnline` | `optiradar.device.online` |
| `deviceOffline`, `deviceUnknown` | `optiradar.device.offline` (the payload `status` says `offline` or `unknown`) |
| `geofenceEnter` / `geofenceExit` | `optiradar.geofence.entered` / `optiradar.geofence.exited` |
| `deviceOverspeed` | `optiradar.device.overspeed` |

Only devices that belong to a tenant (their group, or an ancestor group, has the attribute `optinexusTenantId`, a UUID)
are reported, and that tenant is the event's tenant. Raw positions are never sent. Each event is first written to the
table `tc_optinexus_events` (the outbox) next to the normal event, and a scheduled task delivers it. A row is
`DELIVERED` only after OptiNexus accepted it, it is sent under its own id as `event_id` (a retry never makes a second
event), and OptiNexus being down loses nothing: network errors, 5xx, 401, 408, 429 and an event type that is not yet
in the OptiNexus Event Catalog are retried with growing delay (2 minutes after the first attempt, doubling up to
1 hour, `optinexus.events.maxAttempts` attempts). Any other refusal (payload does not match, application not assigned
to the tenant) parks the row as `FAILED`; after fixing the cause put it back with
`UPDATE tc_optinexus_events SET status = 'PENDING', attempts = 0, lastattemptedat = NULL WHERE status = 'FAILED'`.
Delivered rows are deleted after `optinexus.events.retentionDays` days.

Settings (all in `conf/optiradar.xml`; `setup/optiradar-optinexus.xml` has them):

| Key | Meaning |
|---|---|
| `optinexus.events.enable` | Turn reporting on (default `false`). Events that happen while it is off are not reported later. |
| `optinexus.baseUrl` | OptiNexus address, for example `https://nexus.example.com`. |
| `optinexus.clientId`, `optinexus.clientSecret` | Service account of the OptiRadar application in OptiNexus, with the `event.write` scope. |
| `optinexus.events.interval` | Seconds between deliveries (default 30). |
| `optinexus.events.batchSize` | Events per delivery run (default 50). |
| `optinexus.events.maxAttempts` | Attempts before an event is parked (default 20). |
| `optinexus.events.retentionDays` | Days a delivered event stays in the table (default 7). |
| `event.status.enable` | OptiRadar's own switch for online/offline/unknown events; without it there are none to report (default `false`). |

In OptiNexus the five events must be in the Event Catalog first (`php artisan db:seed
--class=OptiRadarEventCatalogSeeder`) and the OptiRadar application must be assigned to the tenant. The schema change
(`tc_optinexus_events`) is applied by the normal database migration at server start.

## Build and deploy

OptiRadar is a fork of Traccar. The integration lives in **both** parts, so neither the stock `traccar/traccar`
image nor the upstream web app has it:

1. Server (this repository): `./gradlew assemble` builds `target/tracker-server.jar`; the Docker files in `docker/`
   package it (`optiradar-other-<version>.zip`) and the release workflow builds the installers and the image
   `ghcr.io/<owner>/optiradar`, with the web app taken from the OptiRadar-web repository.
2. Web app (the OptiRadar-web repository): `npm ci && npm run build`, then point `web.path` at the `build` folder
   (or place it where the server expects `./web`). The logout redirect and the app switcher come from this part.

Build once per release and deploy the result; other platforms do not build anything of OptiRadar. They only need
the running OptiRadar address, the OIDC client registered in OptiNexus, and for the telematics connector the group
attribute described below.

## Onboarding a tenant

Create a group per tenant and set the attribute `optinexusTenantId` to the OptiNexus tenant id (OptiRadar → Settings →
Groups → Attributes). Put the tenant's devices in that group. The OptiNexus telematics connector reads the same attribute to
know which tenant a device belongs to, and links devices to OptiFleet vehicles by registration number.

## Notes

* Tests: `OpenIdProviderTest` (whole sign-in against a simulated provider with real signed tokens: state, nonce,
  PKCE, replay, login CSRF, concurrency, tenant switch), `OpenIdPendingLoginsTest`, `OpenIdIdTokensTest`
  (signature, issuer, audience, expiry, nonce, algorithm confusion, key rotation), `OpenIdIdentitiesTest` (links,
  changed and reused email, conflicts, races), `OpenIdTenantLinkerTest`, `OpenIdAppsTest`, `OpenIdLifecycleTest`,
  `OpenIdLogoutTokensTest`, `OptinexusEventRecorderTest`, `OptinexusEventRelayTest`. A round trip against a running
  OptiNexus and the delivery of events are not covered by an automated test.

## Upgrading an installation from before the rename

Earlier builds installed as Traccar: `/opt/traccar`, `conf/traccar.xml`, service `traccar`. The Linux installer moves
such an installation to `/opt/optiradar` as a whole (configuration, H2 database in `data/`, logs), renames the
configuration file to `conf/optiradar.xml` and replaces the `traccar` service with `optiradar`. Nothing in the
configuration keys, the database or the API changes, so OptiNexus and OptiFleet keep working without changes.
On Windows, uninstall the old Traccar service first and copy its `conf` and `data` folders into the new OptiRadar
folder. Docker deployments keep their own compose file; the samples in `docker/compose/` are for new installations.
