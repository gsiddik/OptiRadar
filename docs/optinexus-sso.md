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
* `openid.allowRegistration=false` (the default) rejects people who have no OptiRadar account yet. Decide per
  deployment; with `true`, new accounts get `users.defaultDeviceLimit` and have no devices except through their group.
  Consider `users.defaultDeviceLimit=0` so tenant users cannot create devices outside their group.

## Onboarding a tenant

Create a group per tenant and set the attribute `optinexusTenantId` to the OptiNexus tenant id (Traccar → Groups →
Attributes). Put the tenant's devices in that group. The OptiNexus telematics connector reads the same attribute to
know which tenant a device belongs to, and links devices to OptiFleet vehicles by registration number.

## Notes

* Upstream behavior kept as is: the `state` value of the authorization request is not checked on the callback, and the
  ID token is not verified separately (user info is fetched from the provider's endpoint with the access token).
* Tests: `OpenIdTenantLinkerTest`, `OpenIdAppsTest`. The full login round trip against a running OptiNexus is not
  covered by an automated test.
