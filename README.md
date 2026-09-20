# Better Auth FIPA

Attested first-party authentication for native iOS and Android apps, powered by
Better Auth. FIPA stands for First-Party Applications. This workspace contains
the server plugin and its companion React Native library.

The alpha `/first-party` entries implement attested native login and session
lifecycles on both platforms:

- **iOS:** Apple App Attest registration and returning assertions, bound to the
  client's DPoP signing key.
- **Android:** hardware attestation of the actual DPoP signing key, plus
  standard Google Play Integrity requests. Hardware-key evidence and Play
  interaction verdicts are verified separately.

Both platforms support proof-bound access, restart/refresh, logout and
credential retirement. Opt-in legacy protocol coexistence supports clients using
the existing protocol.

> [!WARNING] These packages are alpha software. APIs and database schemas may
> change before the first stable release.

Drizzle/PostgreSQL consumers must apply the
[documented Better Auth 1.7.5 compatibility patch](packages/better-auth-fipa/README.md#drizzlepostgresql-compatibility).

| Workspace                                                   | Purpose                                                                                                     |
| ----------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| [Server plugin](packages/better-auth-fipa/README.md)        | `@eventyr-tech/better-auth-fipa` package; verification, credential lifecycle, grants, and OAuth integration |
| [React Native client](packages/react-native-fipa/README.md) | iOS/Android attestation, native key and secure-session management, and the first-party client lifecycle     |
| [Example server](apps/example-server/README.md)             | Persistent SQLite reference for native login, proof-bound sessions and protected access                     |
| [Example mobile](apps/example-mobile/README.md)             | Expo reference app consuming the native package on iOS and Android                                          |

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

## Development

Use Node.js 22.13+ and pnpm 10.34.5. Both packages require Node.js 22.13+.
Native builds require Xcode and CocoaPods for iOS, and JDK 17 plus the Android
SDK for Android. Attestation requires supported physical devices; the example
has no simulator or software-key bypass.

```sh
pnpm install --frozen-lockfile
pnpm check
pnpm test:ios
pnpm verify:ios-package # macOS: isolated packed consumer and unsigned device build
pnpm test:postgres
pnpm test:android
pnpm verify:android-app # Android SDK/Java: isolated consumer and test-signed APK
```

`pnpm check` runs formatting, builds, lint, types, coverage, and packed-package
checks through one Turbo scheduler. Workspace package manifests own their tasks.
`pnpm test:ios` runs the Swift key-identifier storage tests; native app builds
are separate from those host tests. PostgreSQL uses the existing disposable test
service contract documented in [CONTRIBUTING.md](CONTRIBUTING.md).

For a focused change:

```sh
pnpm exec turbo run lint typecheck test:coverage --filter=@eventyr-tech/react-native-fipa
```

The workspace root is private; the server and React Native libraries are
separate packages. The native package includes Swift/Objective-C++ and Kotlin
sources, CocoaPods and Codegen specifications, and compiled TypeScript.

## Architecture

See [the authentication architecture](docs/design.md) for platform trust,
protocol ownership, account lifecycle and extension boundaries.

Report vulnerabilities through the process in [SECURITY.md](SECURITY.md).
