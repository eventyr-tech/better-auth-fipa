# React Native FIPA

`@eventyr-tech/react-native-fipa` supplies the iOS and Android native
counterpart to `@eventyr-tech/better-auth-fipa`. The local alpha includes App
Attest, Android hardware-attested DPoP keys and standard Play Integrity.

> [!WARNING] This package is alpha software. Its API may change before the first
> stable release.

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

## Installation

```sh
pnpm add --save-exact @eventyr-tech/react-native-fipa@alpha react-native-dpop@1.0.0
```

Use this client with `@eventyr-tech/better-auth-fipa` on the server.
Drizzle/PostgreSQL servers also require the dependency patch documented in the
server package's README; no such patch is needed in the mobile app.

Install iOS pods after adding the package. React Native 0.86 and React 19.2 are
the initial integration targets. Expo applications need a development build or
prebuilt native app; Expo Go cannot load this module. The package uses React
Native Codegen, Swift/Objective-C++ on iOS, and Kotlin on Android. Android apps
must set minSdkVersion 28 or higher. There is no software-key or simulated
evidence fallback.

## First-party authentication

The separate `/first-party` entry owns the native authentication lifecycle. The
root and `/core` entries below retain their existing low-level contracts.

```ts
import {
  createNativeFirstPartyClient,
  FirstPartyClientError,
} from "@eventyr-tech/react-native-fipa/first-party";

const sdk = createNativeFirstPartyClient({
  issuer: "https://example.com/api/auth",
  clientId: "mobile-app",
  applicationId: "TEAMID.com.example.mobile",
  environment: "production",
  scopes: ["api:read", "offline_access"],
  resources: [],
  browser: { redirectUri: "com.example.mobile:/auth/callback" },
});
const slot = await sdk.accounts.create();
let state = await sdk.start(slot.slotId);
if (state.kind === "interaction-required" && state.step.kind === "password") {
  state = await sdk.respond(slot.slotId, {
    flowId: state.flowId,
    stepId: state.step.id,
    response: { kind: "password", email, password },
  });
}
```

The host supplies the current email/password from its UI and immediately clears
password input. Render the returned state: password failures remain an
interaction, `attestation` requires `respond` with `{ kind: "attestation" }`,
and `browser-required` requires `openBrowser(slotId, { flowId, stepId })`. Do
not assume one response completes every login. `cancel(slotId)` cancels an
interaction; it can preserve an independently established session.

When the server explicitly enables email OTP, it returns an `authentication`
step with `methods`. Offer only those methods. For email OTP, call `respond`
with `{ kind: "email-otp-request", email }`; the returned `email-otp` step
accepts `{ kind: "email-otp", otp }` or `{ kind: "email-otp-resend" }`. Clear
OTP input immediately after submission. The library binds the recipient on the
server, signs every request and persists replacement continuation handles; the
app never sends the email again with a verification or resend response. A
`temporarily_unavailable` result can include `retryAt` (Unix milliseconds) for
resend guidance. `restore` resumes the typed step without sending another email.
Email and OTP input are not persisted in the native vault.

List persisted slots with `accounts.list()` after restart, let the user select
one, then call `restore(slotId)` to resume an interaction or rotate its refresh
token. Use `sdk.fetch(slotId, url)` for protected requests. It returns a bounded
text response, attaches DPoP and refreshes as needed; consumers do not supply
Authorization headers or store tokens. Application request retries remain the
host's responsibility.

`logout` and `retire` report remote confirmation separately from local state.
Retirement removes exact key references only after confirmation. If issuance
succeeds but session storage fails, the SDK attempts family-only revocation
through the existing logout endpoint, bounded to ten seconds. The operation
still throws its original error; `remoteCleanup` reports `confirmed` or
`unconfirmed` separately from local `cleanup`. Uncertain or lost ownership of
the local write skips remote revocation so a newer runtime's committed rotation
is preserved. There is no background retry queue, and no token is retained in
the error. A lost cleanup response is unconfirmed even if the server revoked it.
`accounts.forget` is allowed only after retirement and key removal.
`accounts.recover` explicitly fences the old slot and allocates a fresh-login
replacement; it retains old keys and does not revoke remote sessions. On iOS,
`accounts.importIOSKeys` and `resumeImport` provide retained-key migration using
exact old storage references, never old tokens or a caller-asserted subject.
Narrow the platform result with `"importIOSKeys" in sdk.accounts` before calling
iOS-only helpers. See the repository migration design before integrating an
existing app.

Handle `FirstPartyClientError.code` in the host UI without logging credentials
or raw native errors. Both platforms use foreground when-unlocked storage and
have no consumer storage/crypto/fetch replacement hooks. Configure resources and
callback URIs consistently with the server. See the example app for the complete
UI handling.

## Android configuration

The same `createNativeFirstPartyClient` selects the compiled Android modules.
Configure `applicationId` as the Android package name, `environment` as
`"production"`, and
`android: { cloudProjectNumber: "123456789", securityLevel: "tee" }`. Use
`"strongbox"` to require StrongBox; neither choice permits software keys or
downgrades. Register the matching Android application and OAuth client with the
server's `androidHardware` provider. The decimal project number is public
configuration; Google credentials belong only on the server.

The common account/login/session API is the same as iOS. Android additionally
exposes `storage` (narrow with `"storage" in sdk`). After `vault_key_lost` or
`vault_recovery_pending`, `storage.prepareRecovery()` can return a confirmation
ticket scoped to **all local accounts across every namespace**. Get explicit
user consent before calling
`storage.recover({ confirmationToken: ticket.confirmationToken, discardAllLocalAccounts: true })`.
This discards local session and catalog records, retains signing keys, and
requires fresh login. It never claims remote revocation. Locked/unavailable
storage is not permission to reset. See the example app's confirmation flow and
the canonical design.

## Existing attestation client

```ts
import {
  createNativeDpopClient,
  createReactNativeDeviceAttestation,
} from "@eventyr-tech/react-native-fipa";

const attestation = createReactNativeDeviceAttestation({
  authBaseURL: "https://example.com/api/auth",
  applicationId: "TEAMID.com.example.mobile",
  keyIdStoragePrefix: "Example.AppAttest.v1.",
});
const proofKey = createNativeDpopClient("Example.dpop.user.v1.account-scope");

const { thumbprint } = await proofKey.generateProofAndThumbprint({
  method: "POST",
  url: "https://example.com/api/auth/oauth2/token",
});
const grantToken = await attestation.prepareOAuthGrant("account-scope", {
  clientId: "mobile-app",
  redirectUri: "example:/oauth/callback",
  codeChallenge: pkceChallenge,
  codeChallengeMethod: "S256",
  dpopJkt: thumbprint,
  scope: "openid profile",
});
// Carry grantToken as device_attestation and thumbprint as dpop_jkt.
// Use proofKey.generateProof() when exchanging the code with the PKCE verifier.
```

`pkceChallenge` is prepared by the host's existing OAuth integration. The client
handles key registration when needed, creates a separate assertion, verifies it,
and returns the resulting one-time grant. It preserves all supplied binding
fields, including resources and nonce. The server independently validates the
configured application and binding.

`prepareCredentialIssuanceGrant(scope, binding)` supports the server's
namespace/subject/DPoP issuance contract. The host still authenticates the
issuance ceremony, verifies DPoP possession, consumes the grant, and issues its
own credential. The SDK does not replace user authentication, session storage,
PKCE generation, navigation, or the host's token refresh logic.

For a custom host authorization endpoint that verifies evidence itself, use
`withOAuthEvidence(scope, binding, consume)` and perform the server request in
`consume`. This holds the per-key lock through verification. The lower-level
`prepareOAuthEvidence()` returns `{ challengeToken, keyId, evidence }`; its
caller must serialize generation and server verification through completion.

The exported `./core` entry provides platform-independent orchestration and
explicit native adapters for integration testing or other native hosts. It does
not contain a permissive verifier; all evidence still passes the server's
configured provider. Applications normally use the default native entry.

## Key ownership and recovery

- Apple's App Attest service owns the private attestation key. The library
  stores only the key identifier in UserDefaults, using the configured prefix
  followed by the lowercase SHA-256 hex digest of the supplied credential scope.
- `react-native-dpop` owns the separate DPoP private key. This client always
  requires hardware backing and never exports private keys to JavaScript.
- Preserve storage prefixes, credential scopes, and DPoP aliases across
  upgrades. Scope construction and environment separation are host policy. Use a
  distinct prefix/alias namespace for independent servers.
- Returning clients first assert with the existing key. Only
  `DEVICE_ATTESTATION_CREDENTIAL_REQUIRED` triggers one local key replacement
  and registration attempt. Generic rejection, rate limiting, and network/native
  errors do not reset keys or loop.
- Ordinary logout retains keys. `resetKey(scope)` removes the local App Attest
  identifier for explicit recovery; it does not delete Apple's private key or
  retire the server credential. `proofKey.deleteKey()` is explicit local DPoP
  retirement; revoke associated host sessions before discarding the key.
- Grant operations serialize by storage prefix and scope across client instances
  in one JavaScript runtime. Multiple runtimes/processes sharing the same native
  storage require host coordination; they are not supported concurrently.

`DeviceAttestationClientError` contains a generic message, a bounded error code,
and optional HTTP status/retry delay. Raw server messages, native exceptions,
and evidence are not attached. A supplied fetch wrapper must also redact these
values. Use HTTPS outside a controlled local test network. Attestation requests
omit cookies and request redirect rejection.

## Validation

The first-party SDK uses an atomic Keychain slot record, native leases and
session generations to fence late writes across runtimes within one app process.
Uncertain refresh outcomes favor fresh login. Shared access from app extensions
or other processes is unsupported. Native transport rejects redirects, omits
cookies/cache and bounds response size. The signing key remains in the Secure
Enclave; the access token stays in SDK memory and the refresh capability is held
in the native vault.

DPoP nonce handling permits one retry of the exact request after an explicit
`use_dpop_nonce` rejection: HTTP 400 with the OAuth JSON error for authorization
requests, or HTTP 401 with an unambiguous DPoP `WWW-Authenticate` challenge for
resources. Both require a valid `DPoP-Nonce` header. The SDK signs a fresh proof
with the nonce through either native signer. The nonce is request-local, never
shared across issuers or resources. Redirects, malformed challenges, repeated
challenges, timeouts and lost responses cannot cause further retries. Resource
servers must issue this rejection before performing the requested operation.
These challenge forms follow
[RFC 9449 sections 8–9](https://www.rfc-editor.org/rfc/rfc9449.html#section-8).

```sh
# From the workspace root:
pnpm exec turbo run lint typecheck test:coverage package:check --filter=@eventyr-tech/react-native-fipa
pnpm test:ios
```

The TypeScript integration suite exercises the actual Better Auth plugin with
synthetic native evidence; Apple's cryptographic verification remains covered by
the server's existing fixtures. Swift tests cover identifier storage, existing
alias compatibility, and vault concurrency/recovery with an injected atomic
store. Native transport tests use real loopback sockets, and DPoP encoding tests
use ephemeral software keys. They do not verify physical Keychain lock/restore
behavior or Secure Enclave key retention. Neither suite substitutes for the
physical-device example.

### Local HTTP development

`createNativeFirstPartyClient` accepts the existing `allowInsecureLoopback`
configuration option. It defaults to `false`. For Eventyr's local simulator and
Maestro Studio setup, merge these fields into the normal client configuration:

```ts
{
  issuer: "http://eventyr.localhost:3000/api/auth",
  allowInsecureLoopback: __DEV__,
}
```

With the option enabled, HTTP is accepted for `localhost`, valid DNS subdomains
such as `eventyr.localhost` and `a.b.localhost`, and the existing `127.0.0.1`
and `[::1]` loopback literals. Hostname checks use parsed hosts, ignore case,
and accept one terminal DNS dot on localhost names (for example,
`eventyr.localhost.`). Subdomain labels must contain 1–63 ASCII letters, digits,
or internal hyphens; the full name without its terminal dot must not exceed 253
characters. Ports such as `:3000` are supported. Empty labels, repeated terminal
dots, `notlocalhost`, `localhost.example.com`, and `eventyr.localhost.evil.com`
are rejected. LAN IPs and Android's `10.0.2.2` host gateway are not part of this
exception.

The policy applies to issuer/key-adapter validation, protected resource
requests, and iOS/Android HTTP and browser authorization URL checks. Resource
origins must still be explicitly allowed by the issuer/resources configuration.
The terminal dot is retained in URLs: dotted and undotted names are distinct
origins and issuer identities, so use one spelling consistently in client/server
settings. URL credentials, native HTTP redirects, ambient cookies/credentials,
and nonlocal HTTP remain prohibited. HTTPS certificate validation is unchanged.

The option does not configure DNS, routing, or the operating system's transport
policy. Ensure the name resolves to the intended local server from each runtime;
on an Android device/emulator, loopback refers to that device/emulator (port
forwarding may be needed). Keep these platform exceptions in development builds:

- **iOS:** merge a scoped ATS exception into the app's generated `Info.plist`
  (or Expo `ios.infoPlist` configuration). For the Eventyr hostname:

  ```xml
  <key>NSAppTransportSecurity</key>
  <dict>
    <key>NSExceptionDomains</key>
    <dict>
      <key>eventyr.localhost</key>
      <dict>
        <key>NSExceptionAllowsInsecureHTTPLoads</key><true/>
      </dict>
    </dict>
  </dict>
  ```

  Use lowercase domain keys without ports. To cover all localhost subdomains,
  use a `localhost` entry with `NSIncludesSubdomains` set to `true`. A URL with
  a terminal dot needs a matching dotted exception entry. See Apple's
  [ATS configuration guidance](https://developer.apple.com/documentation/security/preventing-insecure-network-connections)
  and
  [exception domain rules](https://developer.apple.com/documentation/bundleresources/information-property-list/nsexceptiondomains).

- **Android:** merge this domain rule into a debug-only Network Security Config
  XML resource referenced by the app manifest's
  `android:networkSecurityConfig="@xml/network_security_config"`:

  ```xml
  <network-security-config>
    <base-config cleartextTrafficPermitted="false" />
    <domain-config cleartextTrafficPermitted="true">
      <domain includeSubdomains="true">localhost</domain>
    </domain-config>
  </network-security-config>
  ```

  Add explicit domain entries for loopback IPs if those are used. Prefer the
  undotted Eventyr hostname to avoid platform-specific domain matching
  differences. See Android's
  [Network Security Configuration](https://developer.android.com/privacy-and-security/security-config).

These app settings do not change Maestro Studio's JVM trust store. Keeping the
local origin on HTTP avoids introducing a separate local HTTPS certificate trust
requirement; the SDK does not bypass TLS trust on either platform.

### Consuming this change in Eventyr

This change belongs to `@eventyr-tech/react-native-fipa`; no server API, wire
protocol, or native bridge signature changes are required. The boolean option is
unchanged. Both its JavaScript and compiled native implementations must be
updated.

1. Choose the next unused SDK prerelease version after checking npm's current
   versions/dist-tags. Update the SDK version and workspace lockfile, then run
   the repository checks and native consumer checks. Run a package publish
   dry-run; publish to the `alpha` tag only after explicit release
   authorization. The server package does not require a release for this fix.
2. In Eventyr, install that exact SDK version and commit the updated lockfile.
   For prepublication testing, build and pack this SDK and install the resulting
   tarball instead. Keep the existing compatible peer dependencies.
3. Enable the option in local development and apply the scoped platform
   transport configuration above. Preserve the existing issuer path and resource
   settings.
4. Regenerate native projects if managed by Expo, run CocoaPods installation for
   iOS, then rebuild/reinstall the iOS simulator and Android development
   binaries. Restart Metro against the updated package. A Metro reload or OTA
   JavaScript update alone cannot replace the Swift/Kotlin checks in an existing
   binary.
5. Verify cold-start session restoration and authentication from
   `http://eventyr.localhost:3000` in the simulator and Maestro Studio, plus an
   opt-out/nonlocal HTTP rejection. This change permits local HTTP transport; it
   does not change simulator attestation capabilities or server authentication
   policy.

### Explicit iOS Simulator development mode

Starting with `0.1.0-alpha.2`, the supported public factory can run the native
FiPA protocol on iOS Simulator. Install the matching server package
`@eventyr-tech/better-auth-fipa@0.1.0-alpha.1`, install pods and rebuild the
native app; an OTA JavaScript update alone cannot install the new native module.

```ts
import { createNativeFirstPartyClient } from "@eventyr-tech/react-native-fipa/first-party";

const fipa = createNativeFirstPartyClient({
  issuer: "http://eventyr.localhost:3000/api/auth",
  clientId: "eventyr-ios-simulator", // separately registered development OAuth client
  applicationId: "TEAM.io.eventyr.mobile",
  environment: "development",
  ios: { provider: "ios-simulator" }, // explicit opt-in; default is app-attest
  allowInsecureLoopback: true,
  scopes: ["offline_access"],
  resources: [],
});
const account = await fipa.accounts.create();
const next = await fipa.start(account.slotId);
// Render next.step and use fipa.respond for password or email OTP as usual.
```

Configure the server's `iosSimulator` provider as described in the server
README. Both opt-ins are required. Merely setting `environment: "development"`
still uses Apple's development App Attest environment; it does not select
simulator mode. The simulator module checks `targetEnvironment(simulator)`
natively on every key operation. Physical devices reject it with
`simulator_unavailable`, even if JavaScript requests it. Hardware attestation
failure never triggers fallback.

This provider proves possession of **development software keys**, not device
integrity, Secure Enclave storage, genuine-app identity, or App Attest
assurance. Simulator evidence uses the distinct `ios-simulator` provider
identity and only the `development` environment. The SDK owns its software keys,
DPoP signing, Keychain vault, transports, account catalog, leases, session
rotation and cleanup. Its catalog namespace includes provider and environment
even with a custom `storageNamespace`. Simulator keys also use a separate native
Keychain tag domain. Hardware retained-key import is rejected in simulator mode.
Use separate OAuth client IDs and development servers/databases; omit the server
provider from hosted production. A modified client can forge development
evidence: native eligibility is an SDK guard, not a remote hardware security
guarantee.

`allowInsecureLoopback` remains independent and defaults to false. HTTP is
allowed only for loopback addresses, `localhost`, and `*.localhost` (including
`eventyr.localhost`), never arbitrary remote HTTP origins. Simulator mode does
not relax HTTPS or enable browser authentication.

The existing password/email-OTP, `fetch`, `restore`, `logout`, `cancel` and
account lifecycle APIs are unchanged. On relaunch, call `accounts.list()` and
`restore` for a saved slot. Never persist passwords or OTPs yourself. Permanent
native failures now retain actionable `FirstPartyClientError.code` values:
`app_attest_unavailable`, `simulator_unavailable`, `key_unavailable`,
`key_locked` and `key_invalid_input`. `invalid_configuration` covers
incompatible provider, environment and transport configuration. Errors contain
no original native exception, password, OTP, token or proof. Missing keys still
require registration recovery; unknown native failures remain
`operation_failed`.

FiPA establishes authentication; Eventyr owns onboarding. After successful
native email OTP, use `fipa.fetch` to check the account's password status. For
an existing password, `logout` the OTP session and display native password login
with the email prefilled. For a new account, collect name/password once in-app,
submit the host's protected setup operation, end the OTP session as required by
the host's security policy, and authenticate using that same just-entered
password in memory. Do not ask for it a second time or persist it. No external
browser or legacy device-code pairing is needed for these native flows. Existing
legacy rollout APIs remain available and unchanged.
