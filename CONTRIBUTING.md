# Contributing

Before implementing a substantial API or protocol change, open an issue
describing the use case, threat boundary, and compatibility impact.

Workspace development uses Node.js 22.13 or newer and pnpm 10.34.5:

```sh
pnpm install
pnpm check
pnpm test:ios # macOS: native key-identifier storage tests
pnpm test:android # Android JVM tests, AAR assembly and lint
pnpm verify:android-package # compile a separately installed npm package
pnpm verify:android-app # assemble the packed reference consumer as an arm64 APK
```

Both packages and the workspace require Node.js 22.13 or newer. See
[the architecture](docs/design.md) for package responsibilities and
[the device-flow guide](apps/example-mobile/flows/README.md) for physical-device
validation. Run Turbo-managed checks from the workspace root and combine
independent targets in one invocation.

Android native checks require JDK 17, Gradle 8.14.3 and Android SDK platform 36
with build tools 36.0.0. Set `JAVA_HOME` and `ANDROID_HOME`; Gradle must be on
`PATH`, or set `DEVICE_ATTESTATION_GRADLE` to its absolute executable path. The
module uses React Native 0.86's Gradle code-generation plugin and targets
Android API 28 or newer. `test:android` tests crypto, Play request coordination
and the session vault, including encrypted files and separate JVM processes. It
also tests the isolated native HTTP transport against local HTTP/TLS servers,
including redirect refusal, no automatic repeated sends and total deadlines.
Browser coordination has JVM coverage; Robolectric exercises activity and
manifest wiring on API 28 and 35 with JDK 17. It downloads its framework test
artifacts on first use. These checks do not execute a real browser, emulate
hardware Keystore or contact Google. `verify:android-package` builds the library
AAR. `verify:android-app` uses the generated Expo project's Gradle wrapper,
installs required NDK/CMake tools, and builds an arm64 APK with the generated
test signing key. It also checks TypeScript, Metro and actual native
autolinking. Allow several GB of disk space for the SDK, transformed
dependencies and native build output. This APK is not a Play-signed release.
Physical-device login and retained-key upgrade remain separate release gates. CI
runs these Android checks on a hosted Linux runner without device-lab
credentials.

Run `pnpm test:postgres` against the standard Better Auth PostgreSQL test
service (`user:password@localhost:5432/better_auth`) when changing persistence,
atomic transitions, schema behavior, or Better Auth adapter integration. The
ordinary suite runs the same contract through Better Auth's default SQLite test
instance on Node.js 22.5 and newer. The Kysely development dependency remains
pinned to `0.28.17` as the adapter contract-test baseline. Better Auth, its core
package, and the OAuth Provider are pinned to stable `1.7.5` in this workspace.

`pnpm test:drizzle` runs the same PostgreSQL contracts through Drizzle 0.45.2
with explicit schema mapping, plural model names and real transactions. Each
fixture generates its schema with the public `auth@1.7.5` CLI API and applies
Drizzle-generated migrations in an isolated PostgreSQL schema. It also covers
UInt32 storage, host pairing grants, legacy/native ownership races, claims,
OTP/profile hooks, refresh, retirement and rollback.

Set `TEST_DATABASE_URL` to use a dedicated local test service instead of
port 5432. Never point these commands at an application or production database.
The test user must be allowed to create and drop test schemas and inspect its
own blocked PostgreSQL queries for the deterministic row-lock regression.

```sh
TEST_DATABASE_URL=postgres://user:password@127.0.0.1:55438/better_auth pnpm test:drizzle
TEST_DATABASE_URL=postgres://user:password@127.0.0.1:55438/better_auth pnpm test:consumer
```

`test:consumer` builds and packs both packages, installs them outside the
workspace with Better Auth 1.7.5, React 19.2.3, React Native 0.86.0 and
react-native-dpop 1.0.0, checks public exports and declarations, then runs the
Drizzle contracts against the server tarball's compiled code. Its printed
temporary directory retains the exact tarballs and harness for diagnosis. Native
compilation remains covered by the separate iOS/Android consumer jobs.

The workspace and isolated consumer both install the committed pnpm patch for
`@better-auth/drizzle-adapter@1.7.5`. It is the runtime change from
[upstream PR #11331](https://github.com/better-auth/better-auth/pull/11331),
pinned to commit `d14b9fa8cd5d16563f2a47cac05567d6501446c0`, and rechecks the
update guard after a PostgreSQL lock wait. Do not skip the concurrency tests or
replace the adapter with a test shim. The server package ships the same patch in
`docs/`; consumers must explicitly install it as described in its README. When a
fixed upstream release passes the full contracts, remove the patch, its
configuration, the documentation-copy step, and the consumer patch-file
assertion together.

The dedicated PostgreSQL CI job runs on Node.js 22. Node.js 20 is no longer a
supported runtime or validation target.

Pull requests should include focused tests, avoid undocumented Better Auth
internals, preserve generic database-adapter compatibility, and update
`docs/design.md` when they change a documented contract.

Do not include real attestation objects, assertions, challenges, key
identifiers, DPoP proofs, credentials, or production request bodies in fixtures,
issues, logs, or pull requests.

## Publishing the alpha pair

The server and React Native package manifests are the source of truth for
release versions. Validate and publish them as a compatible pair. Both manifests
default to public access and the `alpha` dist-tag. Do not promote alpha releases
to `latest`.

Publish only after the PR is reviewed and merged, from a clean checkout of the
exact main commit whose Node 22/24, PostgreSQL (Kysely and patched Drizzle),
iOS, and Android CI checks passed. Physical-device evidence must cover the
native implementation being released; tests/docs-only changes do not require
repeating unchanged device flows. npm publishing requires an account authorized
for the `@eventyr-tech` scope and any required interactive authentication. No
publish workflow or registry credentials are stored in this repository.

```sh
git status --short # must be empty
git rev-parse HEAD # match the reviewed, green main commit
pnpm install --frozen-lockfile
pnpm check
# Use a dedicated PostgreSQL test database, never an application database.
TEST_DATABASE_URL=postgres://user:password@127.0.0.1:55438/better_auth pnpm test:postgres
TEST_DATABASE_URL=postgres://user:password@127.0.0.1:55438/better_auth pnpm test:drizzle
TEST_DATABASE_URL=postgres://user:password@127.0.0.1:55438/better_auth pnpm test:consumer
npm whoami
npm view @eventyr-tech/better-auth-fipa versions --json
npm view @eventyr-tech/react-native-fipa versions --json
```

A registry 404 is expected before each package's first publication; an existing
version cannot be overwritten. Keep a record of the source commit and both
published versions. Publish from the workspace so pnpm resolves workspace
references when packing:

```sh
pnpm --filter @eventyr-tech/better-auth-fipa publish --access public --tag alpha
pnpm --filter @eventyr-tech/react-native-fipa publish --access public --tag alpha
npm view @eventyr-tech/better-auth-fipa dist-tags --json
npm view @eventyr-tech/react-native-fipa dist-tags --json
TEST_DATABASE_URL=postgres://user:password@127.0.0.1:55438/better_auth pnpm test:published
```

`test:published` installs the exact manifest versions from npm (not local
tarballs), checks the shipped compatibility patch, public exports and native
declarations, and runs the full server Drizzle contracts. If one publication
succeeds and the other fails, finish the missing publication without attempting
to republish or overwrite the successful version. Announce the pair only after
the registry verification succeeds.

For development-provider changes, run the shared TypeScript integration suite.
It exercises the real software evidence/DPoP implementation against Better Auth
password, OTP, token, resource and lifecycle endpoints for both platform
selections. Its native vault and transport ports are test doubles; recreating
the client verifies persisted-state recovery, not an actual device process
relaunch.

Consumer development authentication and plugin release verification are
distinct. Keep the native iOS/Android package, storage, transport and signed
physical-device attestation checks in the release lifecycle. Software-provider
tests do not certify App Attest, Play Integrity, hardware key storage or native
bridges.
