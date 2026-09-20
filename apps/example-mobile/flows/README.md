# Shared physical-device lifecycle test

Run `lifecycle.yaml`, not this whole directory. It runs login, protected API,
restart/refresh, logout, fresh login with retained keys, and retirement in
order. Helpers intentionally depend on the previous step's state. Only
restart/login relaunch the app. No flow clears app storage or the keychain.

Both platforms use the same React Native test IDs and flows. The Android Cloud
project input is conditional. Platform-specific key-loss diagnostics remain
separate work: Android vault-key loss and iOS DPoP-key loss are different cases.

## Prerequisites

Install a newly signed lab build containing these test IDs. For Android's
LICENSED Play Integrity policy, update through the existing Play test track; do
not substitute a locally signed APK. Keep package `io.eventyr.attestationlab`.
The device must reach an example server configured for its attestation provider.
The previous iOS-only server configuration cannot verify Android evidence.

Create a private env file (outside the repository, mode 600):

```dotenv
TEST_SERVER_URL=https://your-lab-server
TEST_APPLICATION_ID=io.eventyr.attestationlab
TEST_CLOUD_PROJECT_NUMBER=YOUR_GOOGLE_CLOUD_PROJECT_NUMBER
TEST_EMAIL=your-test-account
TEST_PASSWORD=your-test-password
TEST_SUBJECT=your-test-account-subject-id
```

For iOS, `TEST_APPLICATION_ID` is the full Apple App ID (team ID plus bundle
ID). Use the password belonging to the selected test server. `TEST_SUBJECT` is
its Better Auth user ID. Use a dedicated lab account; the flow retires the
credential it creates. Do not run against production. Begin without another
saved slot for that subject, since the restart selector expects one matching
saved account.

Install the pinned local tools from the repository root:

```sh
npm install --prefix .artifacts/maestro-tools --save-exact maestro-runner@1.1.27 yaml@2.8.1 --no-audit --no-fund
```

Using the locally installed Maestro Runner 1.1.27:

```sh
node scripts/device-lab/run.mjs --platform android --device YOUR_ADB_SERIAL \
  --env-file /absolute/private/android.env
```

For iOS use `--platform ios --device YOUR_UDID --team-id YOUR_TEAM`. The command
runs the shared flow and then a separate cleanup flow even when the main flow
fails. Run this wrapper rather than invoking `lifecycle.yaml` directly.

On Android, the wrapper expands these same helpers into a generated root flow
because Runner 1.1.27 does not execute nested shell steps. It replaces
full-field `eraseText` operations with native Select All + Delete, dismisses the
keyboard, and asserts that the focused field's test ID has empty text before
typing. This avoids UIAutomator's `Clear()` reporting success without updating a
React Native controlled input. iOS continues to execute the original shared
helpers. The generated flow is under
`.artifacts/device-screen/android-lifecycle.yaml`.

Reports include JUnit, HTML and failure captures. Treat local reports as
private; captures may show test account data. UI assertions do not independently
verify server-side refresh or revocation. Inspect the corresponding server state
when evaluating those cases. The selective iOS recovery flow includes its own
server-state assertions.

## Android device setup

Enable Developer options and USB debugging. Connect with a data-capable USB
cable, unlock the phone, and approve this Mac's debugging key (Always allow).
Leave Developer options > Stay awake off between jobs. Keep network access
available. Maestro Runner installs its Android automation driver; an OEM
installation permission prompt may require one-time approval.

Removing the screen lock is optional for a dedicated test phone, not required
for an already-unlocked run. ADB cannot bypass a secure lock. A secure lock may
still require manual unlock after reboot or accidental locking. Disabling screen
lock can invalidate credential-protected keys, so configure the test phone
before provisioning test credentials. Do not unlock the bootloader or root it.

## Screen lifecycle

`node scripts/device-lab/run.mjs` runs the shared lifecycle with wake as its
first step, then runs `screen-sleep.yaml` in `finally`, preserving the test's
failure exit code. Cleanup failure also makes the command fail. This avoids
Maestro Runner 1.1.27's unsupported `runShell` inside completion hooks.

Android temporarily sets stay-awake while plugged in, restores the original
setting, and sends SLEEP. iOS uses the selected runner's active WDA connection
to unlock/lock. XCTest owns the active UI test session. No secure-lock bypass is
attempted. Leave normal screen timeouts enabled on both phones.

Add `--probe` to test only wake, lab-app launch and sleep without logging in.
Add `--fail-probe` instead to deliberately fail an assertion and check cleanup.
Neither probe needs an env file or the newly added test IDs. Reports are under
`.artifacts/device-screen/<platform>-jobs`. A failing probe must still leave a
passing sleep-flow report and return a nonzero exit code.

The helper is tied to Maestro Runner 1.1.27's WDA port derivation. Separate iOS
cleanup starts WDA again, so it can briefly wake the display before sleeping it.
Cleanup requires a functioning runner/device connection: SIGKILL, host crashes
and disconnects cannot guarantee it. Android retains its original setting in
`.artifacts/device-screen/<serial>.json` until restored. After reconnection:

```sh
MAESTRO_PLATFORM=android MAESTRO_DEVICE_ID=YOUR_SERIAL node scripts/device-lab/screen.mjs sleep
```

Do not run two jobs against the same device simultaneously.

### iOS selective missing-key recovery

The same local runner can exercise selective key loss. Build the dedicated lab
app with `ATTESTATION_LAB_DIAGNOSTICS=1` and
`EXAMPLE_IOS_BUNDLE_ID=io.eventyr.attestationlab` during iOS prebuild. The
opt-in config plugin adds an app-local native module; ordinary clean prebuilds
omit it, and the reusable SDK contains no key-loss control. Use a clean prebuild
when switching back to an ordinary build so generated diagnostic sources are
removed. The diagnostic deletes the exact Secure Enclave DPoP key for the
selected account slot. It does not delete the vault, App Attest references, or
other keys.

Use a fresh seeded `@example.test` account in an isolated example-server
database. Alongside the usual private flow variables, set `TEST_DATABASE_PATH`
to that local SQLite file and `TEST_EVIDENCE_PATH` to a private output JSON
path. These paths must be available to the host runner. Set `EXAMPLE_PORT` when
the local server needs a different listening port from its public HTTPS URL.

```sh
node scripts/device-lab/run.mjs \
  --platform ios --device "$IOS_DEVICE_UDID" --team-id "$APPLE_TEAM_ID" \
  --env-file /absolute/private/maestro-ios-recovery.env --recovery
```

The flow signs in and verifies protected access, deletes only that slot's DPoP
key, restarts without clearing app data, and requires restore to fail. It checks
that server credentials, families and refresh state are unchanged. Explicit
account recovery then creates a replacement slot, signs in again, and verifies
protected access. The final server assertion requires a distinct App Attest
credential and DPoP thumbprint while retaining the old server credential and
family. This local recovery does not claim to revoke the old remote session. The
runner restores screen settings and sleeps the device even on flow failure.
