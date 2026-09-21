# Better Auth FIPA

`@eventyr-tech/better-auth-fipa` binds Better Auth authorization grants to
evidence from a genuine application instance. The alpha first-party entry
supports iOS with Apple App Attest and Android with hardware-attested DPoP keys
plus standard Google Play Integrity.

> [!WARNING] This package is an alpha. Its API and database schema may change
> before the first stable release.

## Authentication methods and extension boundaries

Native sign-in supports password and server-enabled passwordless email OTP.
Better Auth and the server configuration own authentication policy; the app
renders the supported steps returned by the SDK. Native MFA, TOTP, passkey and
backup-code adapters, and enrollment/settings UI are not included in this
release. An unmet authentication requirement must fail closed.

Provider/key interfaces, server method dispatch and typed SDK continuations are
the existing extension boundaries. Adding another method requires corresponding
server and SDK support; unknown methods are not automatically usable by older
clients. Existing browser APIs remain available, but are not an attestation
bypass or a promise of native MFA support.

## First-party native authentication

The local alpha also exports `androidHardware(options)` from `/first-party`.
Configure hardware key policy, standard Play policy and a server-only
`getAccessToken(signal)` callback. The provider verifies the actual DPoP key's
certificate chain and fresh Play evidence separately; it does not implement
Apple's assertion-counter API or expose alternate verifiers/trust roots. See the
canonical first-party design and the repository's Android reference server for
full configuration.

The alpha `@eventyr-tech/better-auth-fipa/first-party` entry exports
`createNativeFirstPartyPlugin`, `requireNativeAccess`, `requireLegacyAccess`,
and their configuration types. Install it alongside
`createDeviceAttestation(...).serverPlugin` and `oauthProvider(...)`, passing
the same OAuth configuration to the first-party plugin. The optional
`@better-auth/oauth-provider` peer is required for this entry; existing root and
`/client` consumers remain independent of that peer.

The new plugin installs native admission, authorization challenge, token,
browser handoff and logout/retirement integration. It requires a database
adapter with real transactions enabled. Protect application resources with
`requireNativeAccess` so family, credential, scope and DPoP checks apply to
every request. Cookie or generic bearer validation does not replace this guard.

`POST /first-party/logout` normally ends the retained continuation and all its
families. For failed-storage cleanup, the SDK sends `{ "scope": "family" }` with
token-bound DPoP to revoke only the proven token's family. Sibling families and
pending continuations remain usable. This option accepts no target ID and is not
accepted by the credential-retirement endpoint.

See the workspace reference server for executable composition and the bundled
[authentication architecture](docs/design.md) for protocol and lifecycle
responsibilities. The entry accepts the native protocol by default. The explicit
`legacyCompatibility: { clients: [...] }` option adds legacy JSON handling at
the same challenge endpoint, using shared password, OTP and profile-setup
methods. It also enables legacy code exchange and refresh with separate protocol
provenance. Native requests never fall back after a failed proof.

A legacy client policy may set `passwordAcrValues` to explicit host labels for a
fresh password sign-in. Recognized requests retain their selected label as
`assurance.acr`; unknown requirements are rejected. Never configure MFA or
password-setup labels as password-only contexts. This does not create host
assurance snapshots or change token claims. Include the optional private
`firstPartyLegacySession.requestedAcr` field in the database migration.

`allowPasswordReauthentication: true` on a legacy client policy permits an
explicit fresh-password `step_up` using a completed library handle and new PKCE.
Its latest code must already be redeemed into an active legacy family. The user,
client, device key, redirect, scopes and resource stay bound; session expiry and
evidence age do not reset. Include the optional private
`firstPartyLegacySession.authorizationId` column in the migration. This option
does not import existing host handles and remains disabled by default.

`requireNativeAccess` continues to reject legacy tokens. Only resources choosing
to accept the weaker overlap profile should use `requireLegacyAccess`, with the
same configured policies; it still verifies token-bound DPoP and current state.
The legacy adapter handles library-issued continuations and token families. It
does not import a host's pre-existing sessions, authorization codes or tokens.

Use `resolveFirstPartyTokenContext(nativeOptions, info)` inside Better Auth's
`customAccessTokenClaims` callback to distinguish a first-party family reference
from an existing host reference. It reads the current transaction and returns
the verified family identity, original authentication time, requested scopes and
resources, and stored assurance. An absent family returns `null`; an invalid
known family throws instead of falling back to host snapshot semantics. Use the
same callback for JWT issuance and opaque-token introspection. Keep it
read-only; it may run more than once. This resolver is not a token or DPoP
verifier and does not replace `requireNativeAccess` or `requireLegacyAccess`.

## What it provides

- a Better Auth server plugin and inferred client plugin;
- one-time registration and assertion challenges;
- Apple-root-pinned App Attest certificate and assertion verification;
- persistent credential keys, monotonic counters, user binding, and tombstones;
- short-lived grants bound to OAuth, PKCE, resource, nonce, and DPoP inputs;
- purpose-separated grants for attested, DPoP-bound host credential issuance;
- optional Better Auth OAuth Provider enforcement;
- explicit App Attest distribution-metadata policy;
- safe structured diagnostics that exclude authentication material;
- an asynchronous callback for untrusted App Attest receipts.

The plugin does not replace user authentication. It adds application-instance
assurance to a Better Auth flow.

## Requirements

- Node.js 22.13 or newer for the runtime;
- Better Auth `>=1.7.5 <1.8.0` (stable releases);
- `@better-auth/oauth-provider` when OAuth enforcement is used;
- a database adapter that implements Better Auth 1.7 atomic verification-value
  consumption and guarded increments.

## Installation

Install the current alpha with:

```sh
pnpm add @eventyr-tech/better-auth-fipa@alpha
```

Development from this repository uses:

```sh
pnpm install
pnpm check
```

## Server configuration

Create one composition for each Better Auth instance. Do not reuse the same
composition across multiple `betterAuth()` calls.

```ts
import { betterAuth } from "better-auth";
import { oauthProvider } from "@better-auth/oauth-provider";
import {
  appAttest,
  createDeviceAttestation,
} from "@eventyr-tech/better-auth-fipa";

const allowedBuilds = new Set(["42", "43"]);

const attestation = createDeviceAttestation({
  providers: [
    appAttest({
      applications: [
        {
          // Apple App ID: Team ID followed by the bundle identifier.
          appId: "TEAMID.com.example.mobile",
          // This is trusted server policy, not a client-supplied platform.
          platform: "ios",
          environment: "production",
          extensions: {
            // Use "required" once every supported distributed build emits the
            // Apple distribution extensions.
            presence: "if-present",
            // 2 is TestFlight and 4 is the App Store.
            allowedValidationCategories: [2, 4],
            // Apple reports CFBundleVersion, not CFBundleShortVersionString.
            validateBundleVersion: (version) => allowedBuilds.has(version),
          },
        },
      ],
    }),
  ],
  purposes: {
    credentialRegistration: {
      challengeTtlSeconds: 120,
      unboundCredentialTtlSeconds: 86_400,
      expiredCredentialRetentionSeconds: 604_800,
      maxActiveUnboundCredentialsPerApplication: 10,
    },
    oauthAuthorization: {
      protectedClientIds: ["mobile-app"],
      challengeTtlSeconds: 120,
      grantTtlSeconds: 300,
      requireDpopJkt: true,
    },
    credentialIssuance: {
      allowedNamespaces: ["example.device-pairing"],
      challengeTtlSeconds: 120,
      grantTtlSeconds: 300,
      requireDpopJkt: true,
    },
  },
  diagnostics: {
    report(event) {
      telemetry.warn("Device attestation rejected", event);
    },
  },
});

export const auth = betterAuth({
  plugins: [
    attestation.serverPlugin,
    oauthProvider(
      attestation.protectOAuthProvider({
        loginPage: "/login",
        consentPage: "/consent",
      }),
    ),
  ],
});
```

Set `platform: "macos"` for a native macOS application. The provider then
requires Apple's signed ACL Blob to match the documented SIP and Full Security
policy exactly before it trusts the attested key.

Production and development applications must be separate entries with their
matching environment. Configuring a development application never causes its
evidence to match a production application.

## Database schema

The server plugin contributes a `deviceAttestationCredential` model through
Better Auth's plugin schema contract. Generate your application schema after
adding the plugin:

```sh
npx auth@1.7.5 generate
```

Review and apply the generated migration using the workflow for your adapter.
The schema stores a hashed credential lookup key, SPKI public key while active,
the full unsigned 32-bit assertion counter and validation category, user
binding, host-credential binding state, lifecycle status, and the last accepted
distribution metadata. Provider application identities are limited to 255
characters so indexed schema output remains portable across supported adapters.
Raw App Attest evidence, receipts, challenges, key identifiers, DPoP proofs, and
OAuth credentials are not stored in this model.

Model and field-name overrides are not supported by the current alpha.

## Client configuration

The client plugin provides Better Auth endpoint inference and contains no native
Apple implementation:

```ts
import { createAuthClient } from "better-auth/client";
import { deviceAttestationClient } from "@eventyr-tech/better-auth-fipa/client";

export const authClient = createAuthClient({
  plugins: [deviceAttestationClient()],
});
```

The application supplies the native App Attest bridge. Transport encodings are:

| Value                               | Encoding                             |
| ----------------------------------- | ------------------------------------ |
| App Attest key identifier           | Canonical padded base64              |
| Attestation object or assertion     | Canonical padded base64              |
| Returned `clientData`               | Unpadded base64url                   |
| Returned challenge and grant tokens | Opaque strings; do not decode or log |

## Native protocol

### Register an App Attest key

1. Generate an App Attest key and persist its key identifier in platform-secure
   storage.
2. Call `POST /device-attestation/challenge` with `operation: "register"`,
   `purpose: "credential-registration"`, the provider, App ID, and key ID.
3. Decode the returned `clientData`, hash those bytes with SHA-256, and pass the
   hash to Apple's `attestKey` operation.
4. Call `POST /device-attestation/verify` with the challenge token, same key ID,
   and attestation object.
5. Preserve the key ID after `registered-unbound` is returned. Registration does
   not create an OAuth grant.

### Authorize with an assertion

1. Create the OAuth PKCE challenge and non-exportable DPoP key before requesting
   the assertion challenge.
2. Call `POST /device-attestation/challenge` with `operation: "assert"`,
   `purpose: "oauth-authorization"`, and the exact OAuth binding.
3. Hash the returned `clientData` and pass it to Apple's `generateAssertion`
   operation.
4. Verify the assertion through `POST /device-attestation/verify`.
5. Add the returned grant as `device_attestation` and the same DPoP thumbprint
   as `dpop_jkt` on the authorization request.
6. Redeem the code with the matching PKCE verifier and DPoP private key.

### Authorize host credential issuance

Hosts can require the same assurance for a credential that is not an OAuth
token, such as a paired-device credential:

1. Configure a host-owned `credentialIssuance.allowedNamespaces` entry.
2. Create a non-exportable DPoP key and a non-secret subject identifying the
   exact issuance ceremony. Do not use the raw pairing code or credential.
3. Request an assertion challenge with `purpose: "credential-issuance"` and a
   binding containing the configured namespace, subject, and DPoP thumbprint.
4. Verify the assertion through `/device-attestation/verify`.
5. In the host issuance handler, call
   `consumeCredentialIssuanceGrant({ grantToken, binding })` before creating the
   credential, then persist the returned attestation credential ID and the same
   DPoP thumbprint with the host credential.

OAuth integrations that issue tokens outside the authorization-code callback can
similarly call
`consumeOAuthAuthorizationGrant({ grantToken, binding, userId })`. Both
consumers atomically consume the grant and reject a grant made for the other
purpose.

Challenges and grants are short-lived and single-use. A failed or interrupted
attempt obtains a new challenge; clients must never retry the same evidence with
the same token concurrently.

Ordinary refreshes and protected API requests use Better Auth's DPoP binding and
do not generate new App Attest assertions.

## Default limits

| Setting                          |            Default |
| -------------------------------- | -----------------: |
| Registration challenge           |        120 seconds |
| Assertion challenge              |        120 seconds |
| Attestation grant                |        300 seconds |
| Unbound credential lifetime      |           24 hours |
| Expired unbound retention        |             7 days |
| Maximum evidence                 |            128 KiB |
| Challenge endpoint rate limit    | 30 requests/minute |
| Verification endpoint rate limit | 20 requests/minute |

`maxActiveUnboundCredentialsPerApplication` has no default limit in the alpha;
hosts should configure it according to their account and recovery flows.

## Distribution metadata

When extensions are present, the plugin strictly parses
`apple_bundle_version_01` as a string and `apple_validation_category_01` as an
unsigned 32-bit value. The latter accepts Apple's four-byte little-endian
representation and a safe numeric representation for decoder compatibility.

`presence: "required"` rejects evidence without the metadata. Use `"if-present"`
only as an explicit rollout policy for distributed clients that predate the
extensions; malformed or partial metadata is rejected under both policies.

## Receipts

An App Attest receipt remains opaque and untrusted even after the synchronous
attestation succeeds. The optional callback may enqueue it for independent Apple
fraud-risk processing, but its result does not alter the current login. Callback
failures do not weaken or replace the cryptographic verification result. Never
log receipt bytes.

## Diagnostics

The diagnostic callback receives only:

- provider and operation;
- stable failure stage and reason;
- retryability;
- bounded structural measurements when available.

It never receives evidence, assertions, challenges, key identifiers, public
keys, receipt bytes, OAuth codes, DPoP proofs or thumbprints, credentials, or
request bodies. Client responses use stable generic Better Auth error codes and
do not expose internal failure reasons. Diagnostic delivery is best effort and
never delays the authentication response; asynchronous reporters must own their
delivery deadlines, queues, and backpressure.

## Credential lifecycle

- Newly registered credentials are active but unbound.
- The first accepted protected authorization permanently binds the credential to
  that Better Auth user.
- Assertion counters advance through a guarded atomic database update.
- Expired, retired, counter-exhausted, and user-deleted credentials cannot be
  reactivated.
- User deletion preserves a revoked tombstone so the same provider key cannot
  transfer to another account.

Authenticated users can list and retire their own credentials through the
inferred Better Auth endpoints. When the first-party plugin is installed, public
provider retirement and user deletion also invoke its shared logical-credential
retirement routine. Associated native and library-issued legacy families are
revoked and pending codes are cancelled. Resource guards reject even unexpired
JWTs afterward. The routine uses the same transaction and credential-before-key
lock order as native retirement. It does not revoke unrelated host-issued
tokens; standalone low-level users retain their own token-revocation workflow.

## Development and validation

```sh
pnpm check
pnpm test:coverage
pnpm test:postgres
pnpm package:check
```

Plugin integration tests use isolated SQLite databases and PostgreSQL schemas.
The PostgreSQL CI lanes run the shared contracts through Kysely and Drizzle,
including generated schema migrations and an independently installed package
consumer. Other adapters remain unverified until they pass the same contracts.

### Drizzle/PostgreSQL compatibility

The supported Drizzle baseline is Better Auth **1.7.5**, Drizzle ORM **0.45.2**,
and `@better-auth/drizzle-adapter@1.7.5` **with the included compatibility
patch**. Unpatched 1.7.5 does not preserve guarded updates under PostgreSQL
contention. The patch applies the runtime fix from
[Better Auth PR #11331](https://github.com/better-auth/better-auth/pull/11331)
(commit `d14b9fa8cd5d16563f2a47cac05567d6501446c0`) to both adapter entry
points. It does not change this plugin's authentication behavior or add an
adapter shim.

Installing this package does **not** automatically patch your dependencies. In
the server application's workspace root, copy the supplied patch:

```sh
mkdir -p patches
cp node_modules/@eventyr-tech/better-auth-fipa/docs/@better-auth__drizzle-adapter@1.7.5.patch patches/
```

Merge this entry into `pnpm-workspace.yaml`, preserving existing patches:

```yaml
patchedDependencies:
  "@better-auth/drizzle-adapter@1.7.5": patches/@better-auth__drizzle-adapter@1.7.5.patch
```

Run `pnpm install` and commit the patch, workspace configuration, and lockfile.
Keep Better Auth and its adapter pinned to 1.7.5 for this baseline; newer
versions are not implicitly covered by this patch. CI and deployments should use
`pnpm install --frozen-lockfile`. In a monorepo, copy from the server
workspace's `node_modules` if the package is not installed at the root. Remove
the patch only after upgrading to an upstream version containing the fix and
rerunning the PostgreSQL contracts. SQLite/Kysely and PostgreSQL/Kysely do not
need this patch.

See [docs/design.md](docs/design.md) for the authentication architecture,
platform trust distinctions, security invariants and extension boundaries.

## Security

Report vulnerabilities through GitHub private vulnerability reporting as
described in [SECURITY.md](SECURITY.md). Do not put real evidence, assertions,
challenges, key identifiers, DPoP material, credentials, receipts, or production
request bodies in issues or fixtures.

## License

[MIT](LICENSE)

### Opt-in shared development server provider (development only)

`0.1.0-alpha.1` adds `developmentProvider` to the public `/first-party` entry
point for `@eventyr-tech/react-native-fipa@0.1.0-alpha.2` clients. It uses the
same registration, native admission, password/email-OTP, DPoP token, resource
and lifecycle endpoints. It does not redirect native authentication through
legacy device-code pairing.

```ts
import { createDeviceAttestation } from "@eventyr-tech/better-auth-fipa";
import {
  developmentProvider,
  createNativeFirstPartyPlugin,
} from "@eventyr-tech/better-auth-fipa/first-party";

// Execute only in your explicitly selected local/development server composition.
const development = developmentProvider({
  enabled: true,
  environment: "development",
  applicationIds: ["io.eventyr.mobile"],
});
const device = createDeviceAttestation({
  providers: [development],
  purposes: {
    credentialRegistration: {},
    oauthAuthorization: {
      protectedClientIds: ["eventyr-development"],
      requireDpopJkt: true,
    },
  },
});
const applications = [
  {
    clientId: "eventyr-development",
    provider: development,
    applicationId: "io.eventyr.mobile",
    environment: "development" as const,
    scopes: ["offline_access"],
    resources: [],
  },
];
// Supply applications to your existing NativeTokenOptions and install
// device.serverPlugin, the OAuth provider and createNativeFirstPartyPlugin(options).
// Pass the SAME options to requireNativeAccess. Keep explicit lifetime policies,
// the email-otp plugin/delivery configuration, and real database transactions.
```

Register that separate public OAuth client with the normal native grant/scopes
policy. The matching client must explicitly select `provider: "development"` and
`environment: "development"`. Continue to protect resources with
`requireNativeAccess`; a generic JWT or cookie check does not enforce FiPA's
current provider policy. The server does not need a new schema migration for
this provider; existing credential rows are keyed by provider/application/key
identity.

The evidence is a challenge-bound signature by a **software key**. It does not
prove Apple App Attest, a genuine application, physical-device integrity or
Secure Enclave possession. Assurance retains provider `development` and
environment `development`, never `app-attest`. The shared one-time challenge and
database counter CAS prevent replay; its server counter is not an Apple hardware
counter.

The factory requires `enabled: true`, a development environment and an
application allowlist. Production native policies reject it.
`NODE_ENV=production` additionally rejects construction, registration,
admission, token issuance/refresh and protected resource access.
Removing/replacing the native application policy also invalidates development
token authority. App Attest cannot verify development evidence, and hardware and
development credentials cannot be substituted across policies.

**The host application must omit this provider from hosted production**,
including production deployments whose `NODE_ENV` is absent or misconfigured.
Use a separate development OAuth client and server/database. There is no client
runtime eligibility restriction: the same TypeScript provider serves iOS
simulators, Android emulators and development devices. A client cannot establish
its runtime authenticity using software evidence. Production safety depends on
explicit server composition and provider policy.

Keep existing legacy providers and rollout policies in their existing
composition; adding the shared development provider does not migrate or replace
legacy device-code pairing. Profile/password setup and the decision to return an
OTP-authenticated existing-password account to native password login remain host
application policy.
