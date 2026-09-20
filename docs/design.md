# Authentication architecture

Better Auth FIPA pairs a Better Auth server plugin with a React Native client
for attested first-party authentication on iOS and Android. Both packages
require Node.js 22.13 or newer for their JavaScript tooling. The protocol is
based on the
[OAuth 2.0 for First-Party Applications draft, revision 04](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-first-party-apps-04),
with mandatory device attestation and DPoP as additional profile requirements.

See the package READMEs for configuration and exported APIs:

- [`@eventyr-tech/better-auth-fipa`](https://github.com/eventyr-tech/better-auth-fipa/blob/main/packages/better-auth-fipa/README.md)
- [`@eventyr-tech/react-native-fipa`](https://github.com/eventyr-tech/better-auth-fipa/blob/main/packages/react-native-fipa/README.md)

## Responsibilities

The application supplies its authentication screens, account selection and
business logic. It renders the SDK's typed continuation steps and submits user
responses. Better Auth and the server configuration determine authentication
policy and enabled methods.

The SDK manages native key references, attestation, PKCE, DPoP proofs, account
slots, continuation handles, secure token storage, refresh and authenticated
requests. Consumers use `sdk.fetch` for protected resources instead of handling
access or refresh tokens themselves.

The server verifies platform evidence, binds authorization to the proven key,
executes configured authentication methods and manages credentials, sessions,
authorization codes and token families. Resource handlers use
`requireNativeAccess` to enforce proof, scope and current credential/family
state. Cookie authentication or generic bearer-token validation cannot replace
that resource guard.

## Native authentication flow

1. The SDK prepares an account slot and native signing keys.
2. It obtains platform evidence bound to the server's admission challenge and
   the DPoP key. The server verifies that evidence before allowing
   authorization.
3. The SDK sends form-encoded authorization-challenge requests with fresh DPoP
   proofs. The app renders password, configured email-OTP or other supported
   continuation states returned by the SDK.
4. After authentication, the SDK redeems the authorization code using PKCE and
   the bound proof key. It persists session state in the native vault.
5. Protected requests carry token-bound DPoP proofs. Refresh rotates authority
   while retaining the credential and original authentication context.

The client validates continuation responses, including challenge responses with
HTTP 403, and persists replacement handles. A missing or invalid proof never
causes automatic fallback to the legacy protocol.

## Platform trust

### iOS

Apple App Attest registers an attested application key and supplies returning
assertions with a monotonically increasing counter. Admission binds this
application evidence to a separate Secure Enclave DPoP signing key. The server
verifies Apple's certificate chain, application identity, challenge binding and
assertion signature/counter before accepting the evidence.

App Attest and DPoP keys have different roles; App Attest does not directly
attest the DPoP key as an Android hardware-key certificate does. Native private
keys are not exported to JavaScript. The default signing policy requires an
unlocked device.

### Android

Android hardware key attestation verifies the actual DPoP signing key, its
certificate chain, attestation challenge, application identity and configured
security-level policy. Standard Google Play Integrity requests provide a
separate interaction verdict bound to the request hash.

The server evaluates hardware-key evidence and Play app/licensing/device
verdicts separately. A Play Integrity verdict is not a durable credential public
key or an App Attest-style assertion counter. The host supplies its Google
verification credentials and policy; unsupported hardware or rejected evidence
does not silently select software keys or bypass attestation.

## State and recovery

Account slots isolate identities and sessions. The SDK coordinates native vault
writes and concurrent operations so cancellation, logout or retirement cannot be
undone by a late response. Private keys and session material are not exposed in
ordinary application UI or diagnostics.

Logout and credential retirement report remote confirmation separately from
local cleanup. Retirement removes the exact local keys only after the required
confirmation. Local account recovery is distinct: it fences the old slot,
retains its identity references and starts a replacement identity that requires
fresh authentication. It does not imply that the old remote session was revoked.

A missing key fails closed. Restore does not silently generate another key or
reuse a session bound to a different identity. Uncertain refresh outcomes favor
fresh login rather than replaying a request whose consumption is unknown.

Server adapters must support real transactions. One-time admission, code and
refresh consumption, credential binding and revocation use atomic state changes.
A revoked family or credential cannot regain authority through an in-flight
issuance or refresh operation.

## Legacy and lower-level integrations

The root server/client entries retain the App Attest challenge, verification,
credential and grant APIs independently of the higher-level `/first-party`
entry. Optional OAuth Provider composition binds grants to authorization inputs.

The first-party plugin's explicit `legacyCompatibility` option accepts the
legacy JSON protocol at the shared challenge endpoint. Legacy and native
protocol provenance remain distinct. `requireNativeAccess` rejects legacy
families; resources intentionally supporting them use `requireLegacyAccess` with
the corresponding policy. The adapter handles library-issued state and does not
import pre-existing host sessions or tokens.

## Authentication methods and extensibility

Native sign-in supports password and server-enabled passwordless email OTP.
Native MFA, TOTP, passkey and backup-code adapters, and enrollment/settings UI
are not included in this release. Required factors must never be bypassed.
Existing browser APIs remain available for host integrations; they do not
provide an attestation bypass.

Provider/key interfaces, server method dispatch and typed SDK continuations are
the extension boundaries. Adding a method requires corresponding server and SDK
support and tests. An older SDK is not promised to handle unknown future steps.

## Verification boundaries

Server and SDK integration tests cover protocol binding, replay rejection,
method policy, transaction races, refresh, retirement and recovery. Native tests
cover platform storage and transport behavior. Packed-consumer checks verify
exports, autolinking, Codegen and compilation independently of workspace links.

Hardware attestation, Keychain/Keystore behavior and Play verdicts require
signed physical-device tests. Contributor commands and prerequisites are
documented in
[CONTRIBUTING.md](https://github.com/eventyr-tech/better-auth-fipa/blob/main/CONTRIBUTING.md)
and the
[device-flow guide](https://github.com/eventyr-tech/better-auth-fipa/blob/main/apps/example-mobile/flows/README.md).
Test fixtures and reports must not contain production credentials or
authentication material.
