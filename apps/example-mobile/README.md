# Example mobile app

An Expo development-build consumer of the public
`@eventyr-tech/react-native-fipa/first-party` entry. It connects to the
[example server](../example-server/README.md) and exercises account slots,
password login, refresh/restoration, DPoP access, logout, retirement and
explicit recovery. The SDK owns key generation, attestation, PKCE, proofs,
native token storage, continuation state and bounded authenticated transport.

```sh
# From the workspace root:
pnpm install --frozen-lockfile
pnpm exec turbo run build --filter=@eventyr-tech/react-native-fipa
EXAMPLE_IOS_BUNDLE_ID=com.yourcompany.attestationexample \
pnpm --filter @device-attestation/example-mobile prebuild:ios
cd apps/example-mobile/ios
pod install
```

Open the generated Xcode workspace, select your development team, and provision
the chosen bundle identifier with App Attest. The generated app requests the
development entitlement and registers callback scheme
`com.example.deviceattestation`. Build and run on a supported physical iPhone.
Native project folders are generated and gitignored. The scheme is for this
example; consumers must register their own callback in both app and server.

Start Metro from the root:

```sh
pnpm exec turbo run dev --filter=@device-attestation/example-mobile
```

Enter the example server's externally reachable **HTTPS origin** and matching
`TEAMID.bundle.identifier`, then select Connect. Build-time defaults may be set
with `EXPO_PUBLIC_SERVER_URL` and `EXPO_PUBLIC_APP_ATTEST_APPLICATION_ID`; these
are public configuration, not credentials. Plain HTTP is limited to loopback. A
physical phone cannot reach your Mac through `localhost`.

Use this sequence for the signed-device acceptance run:

1. Add account and sign in using the server's seeded account. Call the protected
   account API and verify the confirmed subject.
2. Kill and reopen the app, reconnect with the same configuration, select the
   saved account and restore its session. Call the API again. Also restart the
   server without deleting its database or changing its secret, then restore.
3. Sign out and confirm local sign-out plus the displayed server revocation
   outcome. Sign in again using the retained credential.
4. Retire the credential, confirm server retirement and local key removal, then
   forget its retired catalog entry. A new account slot creates a new
   credential.
5. Exercise explicit recovery separately. It fences the old local slot and
   starts a fresh login in a new one. It retains old key references and **does
   not claim remote revocation** of the old sessions.

The app also renders evidence-renewal and browser-required steps and exposes
cancellation. When configured by the host, the server can offer email OTP; the
app renders method selection, code entry and explicit resend, including retry
guidance. The default server executable uses password-only authentication; MFA
browser acceptance needs a host configured for the factor being tested. A
password is cleared from the input on submission. Tokens, proofs and key
material are never rendered or persisted by the app. The status may show
confirmed account IDs and assurance returned by the protected example API.

`pnpm verify:ios-package` installs an isolated tarball, typechecks this public
API consumer, bundles it with Metro, and checks autolinking, Codegen and
unsigned device compilation. It requires macOS/Xcode and CocoaPods, but no
signing keys. It does not run the signed-device sequence above or prove an
Eventyr upgrade.

There is no simulator attestation or software-key fallback. Android is available
in the local alpha through the same entry, with the acceptance limits below.

## Android

The app uses API 28+ and registers the same exact callback scheme on Android.
Set `EXPO_PUBLIC_ANDROID_APPLICATION_ID` to the package registered for your Play
app and `EXPO_PUBLIC_GOOGLE_CLOUD_PROJECT_NUMBER` to its linked decimal project
number before prebuild. The UI defaults to TEE; select StrongBox to require it.
The matching example server uses Android mode and public client
`example-android`, with production evidence. Server credentials never belong in
either public environment value.

```sh
pnpm --filter @device-attestation/example-mobile prebuild:android
pnpm --filter @device-attestation/example-mobile android
```

A local development build is useful for native integration and UI work, but it
is not genuine Play acceptance. For the attestation run, install a release
through the configured Play testing track with the registered signing
certificate and version. Use a device-trusted HTTPS server origin. The server
requires recognized/licensed app evidence and rejects test verdicts; do not
weaken those checks to make a sideloaded APK pass.

Follow the same login, restart/refresh, protected access, logout and retirement
sequence as iOS. For browser-required steps the installed browser must support
Auth Tab; the SDK does not fall back to an unbound generic browser.

If the encryption key is lost, Connect retains the client so **Recover encrypted
storage** stays reachable. Preparation does not delete anything. The alert
requires explicit confirmation to discard every local account across all SDK
namespaces. The result requires fresh login, preserves signing keys and reports
remote revocation as unconfirmed. A locked device or transient Keystore error
must not result in a reset. Include interruption/resumption and locked-device
behavior in the physical-device run.

`pnpm verify:android-app` installs an isolated packed library, typechecks and
bundles this app, prebuilds it, and assembles an arm64 release APK with the
generated test signing key. It checks actual native autolinking and APK output.
`pnpm verify:android-package` separately builds the packed native AAR. Both are
host build checks; neither installs through Play or proves device attestation.
