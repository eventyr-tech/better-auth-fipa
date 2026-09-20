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

The dedicated PostgreSQL CI job runs on Node.js 22. Node.js 20 is no longer a
supported runtime or validation target.

Pull requests should include focused tests, avoid undocumented Better Auth
internals, preserve generic database-adapter compatibility, and update
`docs/design.md` when they change a documented contract.

Do not include real attestation objects, assertions, challenges, key
identifiers, DPoP proofs, credentials, or production request bodies in fixtures,
issues, logs, or pull requests.
