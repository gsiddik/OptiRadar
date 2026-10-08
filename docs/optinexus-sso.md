# Single sign-on with OptiNexus

OptiRadar signs users in through OptiNexus (OpenID Connect) with Traccar's built-in OpenID client. Two settings,
`openid.tenantClaim` and `openid.tenantGroupAttribute`, tie each login to a tenant. Without `openid.tenantClaim`
nothing below changes and OpenID behaves as in stock Traccar.

## How a login works

1. The user opens `https://<radar>/api/session/openid/auth` (this is the application's launch URL in OptiNexus), or
   uses "Login with OpenID" on the login page. OptiNexus signs them in, or reuses the session they already have from
   OptiFleet, and sends them back to `/api/session/openid/callback`.
2. OptiNexus only issues the login if the user's organization is subscribed to OptiRadar and the user has been given
   access to it. Otherwise the callback shows an error and no session is created.
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

## Configuration (`traccar.xml`)

```xml
<entry key='openid.clientId'>optiradar</entry>
<entry key='openid.clientSecret'>…</entry>
<entry key='openid.issuerUrl'>https://nexus.example.com</entry>
<entry key='openid.allowGroup'>optiradar</entry>   <!-- OptiNexus "groups" claim lists application codes -->
<entry key='openid.tenantClaim'>tenant_id</entry>
<entry key='openid.tenantGroupAttribute'>optinexusTenantId</entry>   <!-- default -->
<entry key='openid.allowRegistration'>true</entry>  <!-- create the account on first SSO login -->
```

* Register OptiRadar as an OIDC client in OptiNexus with the redirect URI
  `https://<radar>/api/session/openid/callback`, and set the application's launch URL to
  `https://<radar>/api/session/openid/auth` so "open OptiRadar" from OptiFleet signs in without a login screen.
* `openid.allowRegistration=false` (the default) rejects people who have no OptiRadar account yet. With `true`, the
  account is created on the first SSO login (only when the tenant has a group), so nobody has to be added by hand.
  Pair it with `users.defaultDeviceLimit=0`: new accounts then cannot create devices of their own and only see the
  devices of their tenant group. The limit blocks *adding* devices only; devices that come through the group stay
  visible. It is applied when an account is created, so it does not change accounts that already exist.
* `setup/traccar-optinexus.xml` is a ready-to-copy sample with these settings. The stock `setup/traccar.xml` is not
  changed, so a plain installation behaves as before. With Docker (`CONFIG_USE_ENVIRONMENT_VARIABLES: "true"`) use
  `OPENID_CLIENT_ID`, `OPENID_TENANT_CLAIM`, `OPENID_ALLOW_REGISTRATION=true` and `USERS_DEFAULT_DEVICE_LIMIT=0`.

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

Limits: a plain logout does not revoke long-lived Traccar API tokens (a deactivation does, because the account is
disabled); the `state` parameter is not checked (upstream behavior).

## Build and deploy

OptiRadar is a fork of Traccar. The integration lives in **both** parts, so neither the stock `traccar/traccar`
image nor the upstream web app has it:

1. Server (this repository): `./gradlew assemble` builds `target/tracker-server.jar`; the Docker files in `docker/`
   package it (`traccar-other-<version>.zip`).
2. Web app (the OptiRadar-web repository): `npm ci && npm run build`, then point `web.path` at the `build` folder
   (or place it where the server expects `./web`). The logout redirect and the app switcher come from this part.

Build once per release and deploy the result; other platforms do not build anything of OptiRadar. They only need
the running OptiRadar address, the OIDC client registered in OptiNexus, and for the telematics connector the group
attribute described below.

## Onboarding a tenant

Create a group per tenant and set the attribute `optinexusTenantId` to the OptiNexus tenant id (Traccar → Groups →
Attributes). Put the tenant's devices in that group. The OptiNexus telematics connector reads the same attribute to
know which tenant a device belongs to, and links devices to OptiFleet vehicles by registration number.

## Notes

* Upstream behavior kept as is: the `state` value of the authorization request is not checked on the callback, and the
  ID token is not verified separately (user info is fetched from the provider's endpoint with the access token).
* Tests: `OpenIdTenantLinkerTest`, `OpenIdAppsTest`, `OpenIdLifecycleTest`, `OpenIdLogoutTokensTest`. The full
  login round trip against a running OptiNexus is not covered by an automated test.
