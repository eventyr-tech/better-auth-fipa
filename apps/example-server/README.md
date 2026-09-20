# Example server

A dedicated device-test server using the public server package and its
`/first-party` entry. It performs native password login, proof-bound code
exchange, rotating refresh, protected API access, logout and credential
retirement. SQLite and the auth secret survive restarts so a device can test
restoration. This is an alpha reference application, not a production
deployment.

Use Node 22.13+ (the example uses `node:sqlite`). From the workspace root, build
the server package:

```sh
pnpm exec turbo run build --filter=@eventyr-tech/better-auth-fipa
```

Create `apps/example-server/.env.local` (gitignored):

```dotenv
EXAMPLE_BASE_URL=https://your-device-test-host.example
APP_ATTEST_APPLICATION_ID=TEAMID.com.example.deviceattestation
APP_ATTEST_ENVIRONMENT=development
EXAMPLE_DATABASE_PATH=.data/example.sqlite
EXAMPLE_AUTH_SECRET=replace-with-your-persistent-random-secret
EXAMPLE_ACCOUNT_EMAIL=tester@example.test
EXAMPLE_ACCOUNT_PASSWORD=replace-with-a-test-account-password
```

Generate the secret once with `openssl rand -hex 32`, save it in that file, and
retain it with the database. The executable requires at least 32 characters and
automatically migrates only its dedicated example database. The seed account is
created once through Better Auth's sign-up pipeline before serving requests;
subsequent starts do not reset its password. Public sign-up and dynamic OAuth
client registration are disabled. Remove the account variables after bootstrap
if desired. Use test credentials, not a production account.

```sh
pnpm --filter @device-attestation/example-server exec node --env-file=.env.local --import tsx src/index.ts
```

The listener uses port 3000 when the base URL has no explicit port. Terminate
TLS at a device-trusted HTTPS proxy or tunnel pointing to it. The external
origin must exactly match the mobile configuration: it participates in issuer
and DPoP binding. The SDK permits HTTP only on explicit loopback, not a Mac's
LAN IP or `.local` hostname. On a physical iPhone, `localhost` is the iPhone
itself.

The server registers public client `example-mobile`, scopes `example:read` and
`offline_access`, and exact browser callback
`com.example.deviceattestation:/auth/callback`. Reusing an existing database
with a different client policy fails rather than silently changing the
registration. The app's development App Attest entitlement must match this
server's environment.

`GET /api/auth/example/account` demonstrates `requireNativeAccess`: it validates
DPoP plus the online token family, credential and scopes before returning the
confirmed subject, credential ID and assurance. A cookie, bearer token, or old
OAuth grant cannot substitute for that check. The UI does not need to obtain or
store an access token.

`createExampleServer` also accepts a `sendEmailOTP({ email, otp })` callback
from the host. Supplying it enables native OTP alongside password login using
the configured sender, five recipient requests per hour with a 60-second resend
interval, and ten requests per credential per hour with a ten-second interval.
Signup stays disabled. The executable leaves this callback unset, so it remains
password-only until a host integrates its delivery service. Do not log OTPs or
return them to the mobile caller. The reference integration tests inject a local
sender and run both methods through durable restart, refresh and logout.

The mobile app renders the server's method list, collects the email/code, and
offers explicit resend. Existing MFA remains a browser step. Better Auth may
remove an unverified account's old password when OTP first proves mailbox
ownership; the example preserves this behavior.

`/login` is a minimal same-origin password page for the system-browser handoff.
It uses a fixed completion target and never follows an arbitrary `callbackURL`.
This example does not configure MFA; applications that enable MFA need a host
login UI implementing those factors. The SDK exposes a browser-required step,
and the library's integration tests cover the MFA handoff independently.

The default iOS executable uses Apple's real verifier. Its integration test
replaces only platform evidence and exercises real SQLite, Better Auth password
handling, PKCE, DPoP and issuance. This does not prove hardware operation.

## Android device-test server

Set `EXAMPLE_PLATFORM=android` and `ANDROID_POLICY_FILE` to a local JSON policy
file. This selects public client `example-android`, production Android evidence
and Google's real verification endpoints. Run it with a separate database from
the iOS example. Stop the iOS instance first if both use the same listener port.
`APP_ATTEST_APPLICATION_ID` and its environment are not needed in Android mode.

The policy file contains `key` and `play` objects, and optionally `trust`
timeout and cache settings. For example (replace the signer placeholder and
choose the version/OS/patch cutoffs for your test device and release policy):

```json
{
  "key": {
    "policyVersion": "android-test-v1",
    "packageName": "com.example.deviceattestation",
    "signingCertificateSets": [
      ["REPLACE_WITH_BASE64URL_SHA256_OF_SIGNING_CERTIFICATE"]
    ],
    "minimumVersionCode": "1",
    "allowedSecurityLevels": ["tee"],
    "minimumOsVersion": 90000,
    "minimumOsPatchLevel": 202601,
    "requireUnlockedDevice": true
  },
  "play": {
    "policyVersion": "android-test-v1",
    "packageName": "com.example.deviceattestation",
    "signingCertificateSets": [
      ["REPLACE_WITH_BASE64URL_SHA256_OF_SIGNING_CERTIFICATE"]
    ],
    "minimumVersionCode": "1",
    "maxAgeSeconds": 120,
    "clockSkewSeconds": 5,
    "requireStrongIntegrity": false
  }
}
```

Each signer entry is a complete accepted signer set. Use the certificate for the
app installed from your Play test track, including Play App Signing where
applicable; the generated APK's test/debug signer is not a substitute. Key
policy version/OS/patch claims describe key creation; Play's minimum version
checks the currently running app. Set `allowedSecurityLevels` to `["strongbox"]`
and the mobile selector to StrongBox when testing that policy. There is no
fallback if the device cannot meet it.

The executable uses Google's
[Application Default Credentials library](https://github.com/googleapis/google-auth-library-nodejs#application-default-credentials)
with the `https://www.googleapis.com/auth/playintegrity` scope. Configure ADC on
the server host for the linked Google project. Keep any credential file outside
the repository and mobile bundle; do not put credentials in the policy JSON or
`EXPO_PUBLIC_*` values. Credential errors and unavailable Google verification
fail closed. The policy loader validates configuration before database migration
and does not obtain a token until verification needs it.

The platform requires a Play-recognized, licensed app and acceptable device
integrity. The verifier rejects test verdicts. A successful APK compilation,
sideload, emulator launch or synthetic integration test does not satisfy the
signed-device acceptance gate. The example's tests verify configuration,
credential cancellation and the real Android challenge route, while the library
suite covers the rest of the lifecycle using synthetic platform evidence.
