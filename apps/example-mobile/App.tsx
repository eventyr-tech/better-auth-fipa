import { useRef, useState } from "react";
import {
  Alert,
  Button,
  Platform,
  NativeModules,
  SafeAreaView,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from "react-native";
import {
  createNativeFirstPartyClient,
  FirstPartyClientError,
  type AccountSlot,
  type ClientState,
  type NativeFirstPartyClient,
} from "@eventyr-tech/react-native-fipa/first-party";

export default function App() {
  const [server, setServer] = useState(
    process.env.EXPO_PUBLIC_SERVER_URL ?? "http://localhost:3000",
  );
  const [appId, setAppId] = useState(
    Platform.OS === "android"
      ? (process.env.EXPO_PUBLIC_ANDROID_APPLICATION_ID ??
          "com.example.deviceattestation")
      : (process.env.EXPO_PUBLIC_APP_ATTEST_APPLICATION_ID ?? ""),
  );
  const [cloudProjectNumber, setCloudProjectNumber] = useState(
    process.env.EXPO_PUBLIC_GOOGLE_CLOUD_PROJECT_NUMBER ?? "",
  );
  const [securityLevel, setSecurityLevel] = useState<"tee" | "strongbox">(
    "tee",
  );
  const [sdk, setSdk] = useState<NativeFirstPartyClient>();
  const [slots, setSlots] = useState<AccountSlot[]>([]);
  const [selected, setSelected] = useState<string>();
  const [state, setState] = useState<ClientState>();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [otp, setOTP] = useState("");
  const [status, setStatus] = useState(
    "Connect to your example server on a signed physical device.",
  );
  const [busy, setBusy] = useState(false);
  const [canCancel, setCanCancel] = useState(false);
  const operation = useRef(0);
  const running = useRef(false);

  async function run(
    action: (checkCurrent: () => void) => Promise<void>,
    preempt = false,
  ) {
    if (running.current && !preempt) return;
    const version = ++operation.current;
    running.current = true;
    setBusy(true);
    setCanCancel(false);
    try {
      await action(() => {
        if (version !== operation.current)
          throw new FirstPartyClientError("cancelled");
      });
    } catch (error) {
      if (version === operation.current) {
        setStatus(
          error instanceof FirstPartyClientError
            ? `Authentication: ${error.code}`
            : "The operation failed. Check the server and device configuration.",
        );
      }
    } finally {
      if (version === operation.current) {
        running.current = false;
        setBusy(false);
        setCanCancel(false);
      }
    }
  }
  async function refreshAccounts(
    client: NativeFirstPartyClient,
    version = operation.current,
  ) {
    const result = await client.accounts.list();
    if (version === operation.current) setSlots(result);
  }
  async function transition(
    action: () => Promise<ClientState>,
    allowCancel = true,
  ) {
    const version = operation.current;
    setCanCancel(allowCancel);
    const next = await action();
    if (version !== operation.current) return;
    setState(next);
    setStatus(
      next.kind === "authenticated"
        ? "Signed in. Keys and tokens are managed by the SDK."
        : next.kind === "signed-out"
          ? "Signed out. Start a fresh login when ready."
          : next.failure
            ? `Continue sign in: ${next.failure}`
            : `Continue sign in: ${next.step.kind}`,
    );
    if (sdk) await refreshAccounts(sdk, version);
  }
  const active = slots.find((slot) => slot.slotId === selected);
  const pending =
    state &&
    (state.kind === "interaction-required" || state.kind === "browser-required")
      ? state
      : undefined;
  const usable =
    active &&
    !["retired", "recovery-required", "import-required"].includes(
      active.status,
    );

  return (
    <SafeAreaView style={styles.screen}>
      <ScrollView
        contentContainerStyle={styles.content}
        keyboardShouldPersistTaps="handled"
      >
        <Text style={styles.title}>First-party authentication</Text>
        <Text>Server origin</Text>
        <TextInput
          testID="server-url"
          accessibilityLabel="Server URL"
          style={styles.input}
          autoCapitalize="none"
          autoCorrect={false}
          value={server}
          onChangeText={setServer}
          editable={!sdk && !busy}
        />
        <Text>
          {Platform.OS === "android" ? "Android package name" : "Apple App ID"}
        </Text>
        <TextInput
          testID="application-id"
          accessibilityLabel={
            Platform.OS === "android" ? "Android package name" : "Apple App ID"
          }
          style={styles.input}
          autoCapitalize="none"
          autoCorrect={false}
          value={appId}
          onChangeText={setAppId}
          editable={!sdk && !busy}
        />
        {Platform.OS === "ios" && NativeModules.AttestationLabDiagnostics && (
          <Button
            testID="lose-dpop-key"
            title="Lab: delete selected DPoP key"
            disabled={busy || !selected}
            onPress={() =>
              void run(async () => {
                const result: string =
                  await NativeModules.AttestationLabDiagnostics.loseDpopKey(
                    selected,
                  );
                setStatus(result);
              })
            }
          />
        )}
        {Platform.OS === "android" && (
          <>
            <Text>Google Cloud project number</Text>
            <TextInput
              testID="cloud-project-number"
              accessibilityLabel="Google Cloud project number"
              style={styles.input}
              value={cloudProjectNumber}
              onChangeText={setCloudProjectNumber}
              keyboardType="number-pad"
              editable={!sdk && !busy}
            />
            <Text>
              Signing key protection:{" "}
              {securityLevel === "tee" ? "TEE" : "StrongBox"}
            </Text>
            <Button
              title="Use TEE"
              disabled={!!sdk || busy}
              onPress={() => setSecurityLevel("tee")}
            />
            <Button
              title="Require StrongBox"
              disabled={!!sdk || busy}
              onPress={() => setSecurityLevel("strongbox")}
            />
          </>
        )}
        {!sdk && (
          <Button
            testID="connect"
            title="Connect"
            disabled={
              busy ||
              !appId ||
              (Platform.OS === "android" && !cloudProjectNumber)
            }
            onPress={() =>
              void run(async (checkCurrent) => {
                const issuer = `${server.replace(/\/+$/u, "")}/api/auth`;
                const client = createNativeFirstPartyClient({
                  issuer,
                  clientId:
                    Platform.OS === "android"
                      ? "example-android"
                      : "example-mobile",
                  applicationId: appId,
                  environment:
                    Platform.OS === "android" ? "production" : "development",
                  ...(Platform.OS === "android"
                    ? { android: { cloudProjectNumber, securityLevel } }
                    : {}),
                  scopes: ["example:read", "offline_access"],
                  resources: [],
                  browser: {
                    redirectUri: "com.example.deviceattestation:/auth/callback",
                  },
                  allowInsecureLoopback: true,
                });
                // Retain the client even if the account catalog is unreadable,
                // so explicit whole-vault recovery remains available.
                setSdk(client);
                const saved = await client.accounts.list();
                checkCurrent();
                setSlots(saved);
                setSelected(saved[0]?.slotId);
                setStatus(
                  "Select a saved account or start a new login. Restore uses the stored refresh token.",
                );
              })
            }
          />
        )}
        {Platform.OS === "android" &&
          NativeModules.AttestationLabDiagnostics && (
            <View>
              <Text>Internal test diagnostics</Text>
              <Button
                title="Inspect vault and signing keys"
                disabled={busy}
                onPress={() =>
                  void run(async () => {
                    const result: string =
                      await NativeModules.AttestationLabDiagnostics.inspect();
                    setStatus(result);
                  })
                }
              />
              <Button
                title="Simulate vault encryption key loss"
                disabled={busy}
                onPress={() =>
                  Alert.alert(
                    "Delete only the vault encryption key?",
                    "Internal test only. Encrypted records and DPoP signing keys remain. Force-close and reopen the app afterward.",
                    [
                      { text: "Cancel", style: "cancel" },
                      {
                        text: "Delete vault key",
                        style: "destructive",
                        onPress: () =>
                          void run(async () => {
                            const result: string =
                              await NativeModules.AttestationLabDiagnostics.loseVaultKey();
                            setStatus(
                              "Vault key deleted. Force-close and reopen. " +
                                result,
                            );
                          }),
                      },
                    ],
                  )
                }
              />
            </View>
          )}
        {sdk && (
          <>
            {"storage" in sdk && (
              <Button
                title="Recover encrypted storage"
                disabled={busy}
                onPress={() =>
                  void run(async (checkCurrent) => {
                    const ticket = await sdk.storage.prepareRecovery();
                    checkCurrent();
                    if (!ticket) {
                      setStatus(
                        "No recoverable storage-key loss was found. Local accounts were not changed.",
                      );
                      return;
                    }
                    Alert.alert(
                      "Discard all local accounts?",
                      "This clears unreadable local sign-ins for every account in this app. You must sign in again. Signing keys are retained; server sessions are not confirmed revoked.",
                      [
                        { text: "Cancel", style: "cancel" },
                        {
                          text:
                            ticket.kind === "recovery-in-progress"
                              ? "Resume recovery"
                              : "Discard local accounts",
                          style: "destructive",
                          onPress: () =>
                            void run(async (stillCurrent) => {
                              await sdk.storage.recover({
                                confirmationToken: ticket.confirmationToken,
                                discardAllLocalAccounts: true,
                              });
                              stillCurrent();
                              setState(undefined);
                              setSelected(undefined);
                              setSlots([]);
                              setPassword("");
                              setOTP("");
                              await refreshAccounts(sdk);
                              stillCurrent();
                              setStatus(
                                "Local storage recovered. Add an account and sign in again. Remote revocation is unconfirmed.",
                              );
                            }),
                        },
                      ],
                    );
                  })
                }
              />
            )}
            <Text style={styles.heading}>Accounts</Text>
            {slots.map((slot, index) => (
              <View key={slot.slotId} style={styles.account}>
                <Button
                  testID={`account-${slot.account?.subject ?? slot.slotId}-${slot.status}`}
                  title={`${selected === slot.slotId ? "Selected: " : ""}${slot.account?.subject ?? `New account ${index + 1}`} · ${slot.status}`}
                  disabled={busy}
                  onPress={() => {
                    setSelected(slot.slotId);
                    setState(undefined);
                    setPassword("");
                    setOTP("");
                    setStatus(
                      "Account selected. Restore or start a fresh login.",
                    );
                  }}
                />
              </View>
            ))}
            <Button
              testID="add-account"
              title="Add account and sign in"
              disabled={busy}
              onPress={() =>
                void run(async (checkCurrent) => {
                  const slot = await sdk.accounts.create();
                  checkCurrent();
                  setSelected(slot.slotId);
                  setState(undefined);
                  await refreshAccounts(sdk);
                  checkCurrent();
                  await transition(() => sdk.start(slot.slotId));
                })
              }
            />
            <Button
              testID="restore-session"
              title="Restore saved session"
              disabled={
                busy ||
                !usable ||
                (!active.hasSession && !active.hasInteraction)
              }
              onPress={() =>
                selected &&
                void run(() => transition(() => sdk.restore(selected)))
              }
            />
            <Button
              testID="fresh-login"
              title="Start fresh login"
              disabled={busy || !usable}
              onPress={() =>
                selected &&
                void run(() => transition(() => sdk.start(selected)))
              }
            />
            {(pending?.step.kind === "password" ||
              pending?.step.kind === "authentication") && (
              <>
                <Text>Email</Text>
                <TextInput
                  testID="auth-email"
                  accessibilityLabel="Email"
                  style={styles.input}
                  autoCapitalize="none"
                  autoCorrect={false}
                  keyboardType="email-address"
                  textContentType="username"
                  value={email}
                  onChangeText={setEmail}
                  editable={!busy}
                />
                {(pending.step.kind === "password" ||
                  pending.step.methods.includes("password")) && (
                  <>
                    <Text>Password</Text>
                    <TextInput
                      testID="auth-password"
                      accessibilityLabel="Password"
                      style={styles.input}
                      secureTextEntry
                      textContentType="password"
                      value={password}
                      onChangeText={setPassword}
                      editable={!busy}
                    />
                    <Button
                      testID="sign-in"
                      title="Sign in"
                      disabled={busy || !email || !password}
                      onPress={() =>
                        selected &&
                        void run(async (checkCurrent) => {
                          checkCurrent();
                          const answer = {
                            kind: "password" as const,
                            email,
                            password,
                          };
                          setPassword("");
                          setOTP("");
                          await transition(() =>
                            sdk.respond(selected, {
                              flowId: pending.flowId,
                              stepId: pending.step.id,
                              response: answer,
                            }),
                          );
                        })
                      }
                    />
                  </>
                )}
                {pending.step.kind === "authentication" &&
                  pending.step.methods.includes("email-otp") && (
                    <Button
                      title="Email a sign-in code"
                      disabled={busy || !email}
                      onPress={() =>
                        selected &&
                        void run(() =>
                          transition(() =>
                            sdk.respond(selected, {
                              flowId: pending.flowId,
                              stepId: pending.step.id,
                              response: { kind: "email-otp-request", email },
                            }),
                          ),
                        )
                      }
                    />
                  )}
              </>
            )}
            {pending?.step.kind === "email-otp" && (
              <>
                <Text>Enter the code sent to your email.</Text>
                <TextInput
                  accessibilityLabel="Email verification code"
                  style={styles.input}
                  value={otp}
                  onChangeText={setOTP}
                  autoCapitalize="none"
                  autoCorrect={false}
                  textContentType="oneTimeCode"
                  keyboardType="number-pad"
                  editable={!busy}
                />
                <Button
                  title="Verify code"
                  disabled={busy || !otp}
                  onPress={() =>
                    selected &&
                    void run(async () => {
                      const answer = { kind: "email-otp" as const, otp };
                      setOTP("");
                      await transition(() =>
                        sdk.respond(selected, {
                          flowId: pending.flowId,
                          stepId: pending.step.id,
                          response: answer,
                        }),
                      );
                    })
                  }
                />
                <Button
                  title="Send another code"
                  disabled={busy}
                  onPress={() =>
                    selected &&
                    void run(() =>
                      transition(() =>
                        sdk.respond(selected, {
                          flowId: pending.flowId,
                          stepId: pending.step.id,
                          response: { kind: "email-otp-resend" },
                        }),
                      ),
                    )
                  }
                />
                {pending.retryAt && (
                  <Text>
                    Try sending again after{" "}
                    {new Date(pending.retryAt).toLocaleTimeString()}.
                  </Text>
                )}
              </>
            )}
            {pending?.step.kind === "attestation" && (
              <Button
                title="Refresh app verification"
                disabled={busy}
                onPress={() =>
                  selected &&
                  void run(() =>
                    transition(() =>
                      sdk.respond(selected, {
                        flowId: pending.flowId,
                        stepId: pending.step.id,
                        response: { kind: "attestation" },
                      }),
                    ),
                  )
                }
              />
            )}
            {pending?.step.kind === "browser-required" && (
              <Button
                title="Continue in secure browser"
                disabled={busy}
                onPress={() =>
                  selected &&
                  void run(() =>
                    transition(() =>
                      sdk.openBrowser(selected, {
                        flowId: pending.flowId,
                        stepId: pending.step.id,
                      }),
                    ),
                  )
                }
              />
            )}
            {selected && ((pending && !busy) || canCancel) && (
              <Button
                title="Cancel login"
                onPress={() =>
                  void run(
                    () => transition(() => sdk.cancel(selected), false),
                    true,
                  )
                }
              />
            )}
            <Button
              testID="protected-api"
              title="Call protected account API"
              disabled={busy || !active?.hasSession}
              onPress={() =>
                selected &&
                void run(async (checkCurrent) => {
                  const result = await sdk.fetch(
                    selected,
                    `${server.replace(/\/+$/u, "")}/api/auth/example/account`,
                    { maximumResponseBytes: 4096 },
                  );
                  checkCurrent();
                  setStatus(
                    result.status === 200
                      ? `Protected API verified this session: ${result.body}`
                      : `Protected API returned ${result.status}`,
                  );
                })
              }
            />
            <Button
              testID="sign-out"
              title="Sign out"
              disabled={busy || !usable}
              onPress={() =>
                selected &&
                void run(async (checkCurrent) => {
                  const result = await sdk.logout(selected);
                  checkCurrent();
                  setState({ kind: "signed-out", slotId: selected });
                  setPassword("");
                  setOTP("");
                  setStatus(
                    `Signed out locally. Server revocation: ${result.remote}. Keys: ${result.keys}.`,
                  );
                  await refreshAccounts(sdk);
                  checkCurrent();
                })
              }
            />
            <Button
              testID="retire-credential"
              title="Retire credential"
              disabled={
                busy ||
                !selected ||
                (!active?.hasSession && active?.status !== "retired")
              }
              onPress={() =>
                selected &&
                Alert.alert(
                  "Retire this credential?",
                  "This revokes its server sessions and removes local key references after confirmation. A later login needs a new credential.",
                  [
                    { text: "Cancel", style: "cancel" },
                    {
                      text: "Retire",
                      style: "destructive",
                      onPress: () =>
                        void run(async (checkCurrent) => {
                          const result = await sdk.retire(selected);
                          checkCurrent();
                          setState({ kind: "signed-out", slotId: selected });
                          setPassword("");
                          setOTP("");
                          setStatus(
                            `Retirement: ${result.remote}. Keys: ${result.keys}.`,
                          );
                          await refreshAccounts(sdk);
                          checkCurrent();
                        }),
                    },
                  ],
                )
              }
            />
            <Button
              testID="recover-account"
              title="Recover with a new credential"
              disabled={busy || !selected || active?.status === "retired"}
              onPress={() =>
                selected &&
                Alert.alert(
                  "Start account recovery?",
                  "The old local session will stop being used. Its key references are retained. Sign in again with a new credential; this does not revoke the old server sessions.",
                  [
                    { text: "Cancel", style: "cancel" },
                    {
                      text: "Recover",
                      onPress: () =>
                        void run(async (checkCurrent) => {
                          const replacement =
                            await sdk.accounts.recover(selected);
                          checkCurrent();
                          setSelected(replacement.slotId);
                          setState(undefined);
                          setPassword("");
                          setOTP("");
                          await refreshAccounts(sdk);
                          checkCurrent();
                          await transition(() => sdk.start(replacement.slotId));
                        }),
                    },
                  ],
                )
              }
            />
            {active?.status === "retired" && active.keysRemoved && (
              <Button
                title="Forget retired account"
                disabled={busy}
                onPress={() =>
                  selected &&
                  void run(async (checkCurrent) => {
                    await sdk.accounts.forget(selected);
                    checkCurrent();
                    setSelected(undefined);
                    setState(undefined);
                    await refreshAccounts(sdk);
                    checkCurrent();
                    setStatus("Retired account removed from the local list.");
                  })
                }
              />
            )}
          </>
        )}
        <Text testID="auth-status" accessibilityLiveRegion="polite" selectable>
          {status}
        </Text>
      </ScrollView>
    </SafeAreaView>
  );
}
const styles = StyleSheet.create({
  screen: { flex: 1, backgroundColor: "#fff" },
  // Keep the last status and controls above Android three-button navigation.
  content: {
    padding: 24,
    paddingBottom: Platform.OS === "android" ? 80 : 24,
    gap: 12,
  },
  title: { fontSize: 24, fontWeight: "600" },
  heading: { fontSize: 18, fontWeight: "600" },
  input: { borderColor: "#777", borderWidth: 1, borderRadius: 6, padding: 10 },
  account: { borderColor: "#ddd", borderWidth: 1, borderRadius: 6 },
});
