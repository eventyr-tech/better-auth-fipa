import { z } from "zod";
import { rejectedDpopNonce } from "./dpop-nonce.ts";
import { FirstPartyClientError } from "./errors.ts";
import {
  retainedIOSIdentitySchema,
  type RetainedIOSIdentity,
} from "./ios-retained-keys.ts";
import {
  authorizationCallback,
  registeredCallback,
} from "./browser-callback.ts";
import {
  createSessionCoordinator,
  type SessionVaultNative,
  type SlotTransaction,
} from "./session-coordinator.ts";

const PROFILE = "device-attestation-fipa-v1";
const digest = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
const identifier = z.string().min(1).max(256);
const capability = z.string().min(1).max(16384);
const accountSchema = z.strictObject({
  subject: identifier,
  credentialId: identifier,
});
export type ConfirmedAccount = z.infer<typeof accountSchema>;
const identitySchema = z.strictObject({
  version: z.literal(1),
  dpopAlias: identifier,
  dpopJkt: digest,
  providerKeyId: z.string().min(1).max(2048),
  providerScope: identifier,
  providerStoragePrefix: identifier.optional(),
  retired: z.literal(true).optional(),
  keysRemoved: z.literal(true).optional(),
  superseded: z.literal(true).optional(),
  account: accountSchema.optional(),
  providerRegistration: z
    .enum(["generated", "attesting", "registered", "unknown"])
    .optional(),
  // The enrollment nonce predates the Android signing key. Persist its server
  // handle with the identity so a restart never invents a new key challenge.
  androidEnrollment: z
    .strictObject({
      keyChallengeToken: digest,
      attestationChallenge: digest,
      issuedAt: z.iso.datetime(),
      expiresAt: z.iso.datetime(),
    })
    .optional(),
});
const bindingSchema = z.strictObject({
  profile: z.literal(PROFILE),
  mode: z.literal("native"),
  issuer: z.url(),
  clientId: identifier,
  provider: identifier,
  applicationId: identifier,
  environment: z.enum(["development", "production"]),
  attemptId: digest,
  codeChallenge: digest,
  codeChallengeMethod: z.literal("S256"),
  dpopJkt: digest,
  scopes: z.array(identifier),
  resources: z.array(z.url()),
});
const stepSchema = z.discriminatedUnion("kind", [
  z.strictObject({
    id: identifier,
    kind: z.literal("authentication"),
    methods: z
      .array(z.enum(["password", "email-otp"]))
      .min(1)
      .max(2)
      .refine((value) => new Set(value).size === value.length),
  }),
  z.strictObject({ id: identifier, kind: z.literal("password") }),
  z.strictObject({ id: identifier, kind: z.literal("email-otp") }),
  z.strictObject({ id: identifier, kind: z.literal("attestation") }),
  z.strictObject({ id: identifier, kind: z.literal("browser-required") }),
]);
const activeSchema = z.strictObject({
  version: z.literal(1),
  phase: z.literal("active"),
  authSession: capability,
  refreshToken: capability.nullable(),
  scopes: z.array(identifier),
  detachedInteraction: z.literal(true).optional(),
  account: accountSchema,
});
const pendingSchema = z.strictObject({
  previousActive: activeSchema.optional(),
  sharesSession: z.literal(true).optional(),
  version: z.literal(1),
  phase: z.literal("interaction"),
  flowId: digest,
  verifier: digest,
  binding: bindingSchema,
  authSession: capability,
  step: stepSchema,
  browser: z
    .strictObject({
      state: digest,
      requestUri: capability,
      redirectUri: z.string().max(2048),
      expiresAt: z.number().int().positive(),
    })
    .optional(),
  retryAt: z.number().int().positive().optional(),
  failure: z
    .enum(["invalid_credentials", "temporarily_unavailable"])
    .optional(),
});
const sessionSchema = z.discriminatedUnion("phase", [
  pendingSchema,
  activeSchema,
]);
type Pending = z.infer<typeof pendingSchema>;
type Session = z.infer<typeof sessionSchema>;
export type NativeIdentity = z.infer<typeof identitySchema>;
export type NativeBinding = z.infer<typeof bindingSchema>;
export interface ResourceResponse {
  url: string;
  status: number;
  headers: Record<string, string>;
  body: string;
}
export interface ResourceRequest {
  method?: "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS";
  headers?: Record<string, string>;
  body?: string;
  maximumResponseBytes?: number;
  signal?: AbortSignal;
}
export interface TerminationResult {
  kind: "signed-out";
  slotId: string;
  remote: "confirmed" | "unconfirmed";
  keys: "retained" | "removed" | "removal-pending";
}
export type ClientState =
  | { kind: "signed-out"; slotId: string }
  | { kind: "authenticated"; slotId: string; account: ConfirmedAccount }
  | {
      kind: "interaction-required" | "browser-required";
      slotId: string;
      flowId: string;
      step: z.infer<typeof stepSchema>;
      hasSession: boolean;
      retryAt?: number;
      failure?: "invalid_credentials" | "temporarily_unavailable";
    };

/** Internal ports. Production adapters must meet these guarantees before export. */
export interface FirstPartyClientPorts {
  browser?: {
    /** External system authentication browser. No lease may span this user interaction. */
    open(
      this: void,
      input: {
        url: string;
        redirectUri: string;
        timeoutMilliseconds: number;
        signal: AbortSignal;
      },
    ): Promise<string>;
  };
  vault: SessionVaultNative;
  crypto: {
    transaction(): Promise<{ id: string; verifier: string; challenge: string }>;
  };
  keys: {
    /** Only called for an empty identity record. Stable slot aliases must recover lost creation results. */
    prepare(
      this: void,
      slotId: string,
      context?: { signal: AbortSignal },
    ): Promise<NativeIdentity>;
    /** Never generates a replacement key. Missing/invalidated keys reject. */
    assertAvailable(this: void, identity: NativeIdentity): Promise<void>;
    /** Idempotent removal of these exact references only, after confirmed retirement. */
    remove(this: void, identity: NativeIdentity): Promise<void>;
    proof(
      this: void,
      identity: NativeIdentity,
      request: {
        url: string;
        method: string;
        accessToken?: string;
        nonce?: string;
      },
    ): Promise<string>;
    /** Registers if necessary and obtains fresh evidence through server verification under this slot lease. */
    admission(
      this: void,
      identity: NativeIdentity,
      binding: NativeBinding,
      context: {
        signal: AbortSignal;
        saveIdentity(identity: NativeIdentity): Promise<void>;
      },
    ): Promise<string>;
  };
  /** Must reject redirects before forwarding credentials, omit cookies/cache, bound response bytes,
   * verify TLS, and honor abort. React Native global fetch is NOT assumed to meet this contract. */
  send(
    this: void,
    request: {
      url: string;
      method: NonNullable<ResourceRequest["method"]>;
      headers: Record<string, string>;
      body: string | null;
      signal: AbortSignal;
      maximumResponseBytes: number;
    },
  ): Promise<{
    url: string;
    status: number;
    body: string;
    headers?: Record<string, string>;
  }>;
}
export interface FirstPartyClientConfiguration {
  issuer: string;
  clientId: string;
  applicationId: string;
  provider: string;
  environment: "development" | "production";
  storageNamespace: string;
  scopes: string[];
  resources: string[];
  accessibility?: "when-unlocked" | "after-first-unlock";
  allowInsecureLoopback?: boolean;
  browser?: { redirectUri: string };
}

/** Use only after configuration validation by the core. */
export function firstPartyStorageNamespace(
  config: FirstPartyClientConfiguration,
) {
  return JSON.stringify([
    config.storageNamespace,
    new URL(config.issuer).href.replace(/\/+$/u, ""),
    config.clientId,
    config.applicationId,
    config.provider,
    config.environment,
  ]);
}

export interface AccountSlot {
  slotId: string;
  status:
    "pending" | "saved" | "retired" | "recovery-required" | "import-required";
  account?: ConfirmedAccount;
  hasSession: boolean;
  hasInteraction: boolean;
  keysRemoved: boolean;
}

/** Internal FiPA state machine. Keys/transport/default native entry and catalog are separate gates. */
export function createFirstPartyClientCore(
  config: FirstPartyClientConfiguration,
  ports: FirstPartyClientPorts,
) {
  config = { ...config };
  let issuer: string;
  try {
    const url = new URL(config.issuer);
    if (
      (url.protocol !== "https:" &&
        !(
          config.allowInsecureLoopback &&
          url.protocol === "http:" &&
          ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)
        )) ||
      url.username ||
      url.password ||
      url.search ||
      url.hash
    )
      throw new Error();
    issuer = url.href.replace(/\/+$/u, "");
    for (const value of [
      config.clientId,
      config.applicationId,
      config.provider,
      config.storageNamespace,
    ])
      identifier.parse(value);
    z.enum(["development", "production"]).parse(config.environment);
    z.array(
      z
        .string()
        .regex(/^[\x21\x23-\x5B\x5D-\x7E]+$/)
        .max(256),
    )
      .min(1)
      .max(32)
      .parse(config.scopes);
    z.array(z.url().max(2048)).max(8).parse(config.resources);
  } catch {
    throw new FirstPartyClientError("invalid_configuration");
  }
  const scopes = [...new Set(config.scopes)].sort();
  const resources = [...new Set(config.resources)].sort();
  const redirectUri = config.browser
    ? registeredCallback(config.browser.redirectUri)
    : undefined;
  const allowedOrigins = new Set([
    new URL(issuer).origin,
    ...resources
      .map((resource) => new URL(resource).origin)
      .filter((origin) => origin !== "null"),
  ]);
  const coordinator = createSessionCoordinator(ports.vault, {
    namespace: firstPartyStorageNamespace(config),
    ...(config.accessibility ? { accessibility: config.accessibility } : {}),
  });
  function activeSession(session: Session | null) {
    return session?.phase === "active"
      ? session
      : (session?.previousActive ?? null);
  }
  function replaceActive(
    session: Session,
    active: z.infer<typeof activeSchema>,
  ): Session {
    return session.phase === "active"
      ? active
      : {
          ...session,
          previousActive: active,
          ...(session.sharesSession ? { authSession: active.authSession } : {}),
        };
  }
  type IssuedCandidate = { identity: NativeIdentity; accessToken: string };
  const issuedCandidates = new WeakMap<SlotTransaction, IssuedCandidate>();
  async function revokeFailedCommit(
    candidate: IssuedCandidate,
  ): Promise<boolean> {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    const deadline = new Promise<false>((resolve) => {
      timer = setTimeout(() => {
        controller.abort();
        resolve(false);
      }, 10_000);
    });
    try {
      const attempt = protectedRequest(
        {
          signal: controller.signal,
          checkpoint: () => {
            if (controller.signal.aborted)
              throw new FirstPartyClientError("cancelled");
            return Promise.resolve();
          },
        },
        candidate.identity,
        candidate.accessToken,
        resourceRequest(`${issuer}/first-party/logout`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ scope: "family" }),
          maximumResponseBytes: 1024,
        }),
      )
        .then(
          (response) =>
            response.status === 200 &&
            z
              .strictObject({ success: z.literal(true) })
              .safeParse(JSON.parse(response.body)).success,
        )
        .catch(() => false);
      return await Promise.race([attempt, deadline]);
    } finally {
      clearTimeout(timer!);
      controller.abort();
    }
  }
  async function run<T>(
    slot: string,
    operation: (tx: SlotTransaction) => Promise<{
      identity: NativeIdentity | null;
      session: Session | null;
      result: T;
    }>,
    signal?: AbortSignal,
    preserveSession = false,
  ): Promise<T> {
    let issued: IssuedCandidate | undefined;
    try {
      return await coordinator.run(
        slot,
        async (tx) => {
          try {
            const update = await operation(tx);
            const active = activeSession(update.session);
            if (active) {
              if (!update.identity)
                throw new FirstPartyClientError("vault_corrupt");
              assertAccount(update.identity, active.account);
              update.identity = { ...update.identity, account: active.account };
            }
            return {
              ...update,
              recoverySession: active
                ? { ...active, detachedInteraction: true }
                : null,
              hasInteraction: update.session?.phase === "interaction",
            };
          } finally {
            issued = issuedCandidates.get(tx);
            issuedCandidates.delete(tx);
          }
        },
        signal,
        { preserveSession },
      );
    } catch (error) {
      if (!issued) throw error;
      const safe =
        error instanceof FirstPartyClientError
          ? error
          : new FirstPartyClientError("operation_failed");
      // If another runtime owns the write, its replacement may use the same
      // rotated family. Never revoke authority we cannot prove was discarded.
      const confirmed =
        safe.cleanup === "complete" && (await revokeFailedCommit(issued));
      throw new FirstPartyClientError(
        safe.code,
        safe.cleanup,
        confirmed ? "confirmed" : "unconfirmed",
      );
    }
  }
  // Access tokens are never serialized to the vault. Match the persisted refresh
  // capability before reuse so another runtime's rotation invalidates this cache.
  const access = new Map<
    string,
    {
      token: string;
      expiresAt: number;
      refreshToken: string | null;
      authSession: string;
    }
  >();
  const cancellations = new Map<string, object>();
  const browsers = new Map<string, AbortController>();
  const ensureCurrent = (
    slot: string,
    version: object | undefined,
    signal?: AbortSignal,
  ) => {
    if (cancellations.get(slot) !== version || signal?.aborted)
      throw new FirstPartyClientError("cancelled");
  };
  const state = (slotId: string, session: Session | null): ClientState => {
    if (!session) return { kind: "signed-out", slotId };
    if (session.phase === "active")
      return { kind: "authenticated", slotId, account: session.account };
    return {
      kind:
        session.step.kind === "browser-required"
          ? "browser-required"
          : "interaction-required",
      slotId,
      flowId: session.flowId,
      step: session.step,
      hasSession: Boolean(session.previousActive),
      ...(session.failure ? { failure: session.failure } : {}),
      ...(session.retryAt ? { retryAt: session.retryAt } : {}),
    };
  };
  function read(tx: SlotTransaction) {
    try {
      const stored = {
        identity:
          tx.identity === null ? null : identitySchema.parse(tx.identity),
        session: tx.session === null ? null : sessionSchema.parse(tx.session),
      };
      const active = activeSession(stored.session);
      if (stored.identity?.keysRemoved && !stored.identity.retired)
        throw new Error();
      if (
        active &&
        (!stored.identity?.account ||
          !sameAccount(stored.identity.account, active.account))
      )
        throw new Error();
      return stored;
    } catch {
      throw new FirstPartyClientError("vault_corrupt");
    }
  }
  function sameAccount(left: ConfirmedAccount, right: ConfirmedAccount) {
    return (
      left.subject === right.subject && left.credentialId === right.credentialId
    );
  }
  function assertAccount(identity: NativeIdentity, account: ConfirmedAccount) {
    if (identity.account && !sameAccount(identity.account, account))
      throw new FirstPartyClientError("invalid_response");
  }
  async function requireIdentity(tx: SlotTransaction) {
    const stored = read(tx);
    if (!stored.identity)
      throw new FirstPartyClientError("reauthentication_required");
    if (stored.identity.retired || stored.identity.superseded)
      throw new FirstPartyClientError("reauthentication_required");
    await ports.keys.assertAvailable(stored.identity);
    await tx.checkpoint();
    return { ...stored, identity: stored.identity };
  }
  async function signedRequest(
    tx: Pick<SlotTransaction, "checkpoint" | "signal">,
    identity: NativeIdentity,
    request: Omit<Parameters<FirstPartyClientPorts["send"]>[0], "signal">,
    accessToken?: string,
  ) {
    // Request-local state prevents nonce reuse across issuers/resources/accounts.
    let nonce: string | undefined;
    for (let attempt = 0; attempt < 2; attempt++) {
      await tx.checkpoint();
      const proof = await ports.keys.proof(identity, {
        url: request.url,
        method: request.method,
        ...(accessToken === undefined ? {} : { accessToken }),
        ...(nonce === undefined ? {} : { nonce }),
      });
      await tx.checkpoint();
      // Thrown transport errors deliberately escape without any retry.
      const response = await ports.send({
        ...request,
        signal: tx.signal,
        headers: { ...request.headers, DPoP: proof },
      });
      if (
        response.url !== request.url ||
        !Number.isInteger(response.status) ||
        response.status < 200 ||
        response.status >= 600 ||
        (response.status >= 300 && response.status < 400) ||
        new TextEncoder().encode(response.body).byteLength >
          request.maximumResponseBytes
      )
        throw new FirstPartyClientError("invalid_response");
      nonce = rejectedDpopNonce(response, accessToken !== undefined);
      if (nonce === undefined) return response;
      if (attempt === 1) throw new FirstPartyClientError("request_failed");
    }
    throw new FirstPartyClientError("request_failed");
  }
  async function post(
    tx: SlotTransaction,
    identity: NativeIdentity,
    path: string,
    parameters: URLSearchParams,
  ) {
    const url = `${issuer}${path}`;
    const response = await signedRequest(tx, identity, {
      url,
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
      body: parameters.toString(),
      maximumResponseBytes: 65536,
    });
    let body: unknown;
    try {
      body = JSON.parse(response.body);
    } catch {
      throw new FirstPartyClientError("invalid_response");
    }
    const retry = Object.entries(response.headers ?? {}).find(
      ([name]) => name.toLowerCase() === "retry-after",
    )?.[1];
    const seconds = retry && /^\d{1,5}$/.test(retry) ? Number(retry) : 0;
    return {
      status: response.status,
      body,
      retryAt:
        seconds > 0 && seconds <= 86400
          ? Date.now() + seconds * 1000
          : undefined,
    };
  }
  async function tokens(
    tx: SlotTransaction,
    identity: NativeIdentity,
    form: URLSearchParams,
    authSession: string,
  ) {
    const response = await post(tx, identity, "/oauth2/token", form);
    if (response.status !== 200)
      throw new FirstPartyClientError("reauthentication_required");
    const parsed = z
      .object({
        token_type: z.literal("DPoP"),
        access_token: capability,
        expires_in: z
          .number()
          .int()
          .positive()
          .max(86400 * 365),
        expires_at: z.number().int().positive(),
        refresh_token: capability.optional(),
        scope: z.string().max(8192),
        auth_session: capability.optional(),
        first_party_account: z.strictObject({
          sub: identifier,
          credential_id: identifier,
        }),
      })
      .safeParse(response.body);
    if (!parsed.success) throw new FirstPartyClientError("invalid_response");
    const account = {
      subject: parsed.data.first_party_account.sub,
      credentialId: parsed.data.first_party_account.credential_id,
    };
    assertAccount(identity, account);
    const granted = parsed.data.scope.split(" ");
    if (
      granted.some((scope) => !scopes.includes(scope)) ||
      parsed.data.expires_at * 1000 <= Date.now() ||
      (granted.includes("offline_access") && !parsed.data.refresh_token)
    )
      throw new FirstPartyClientError("invalid_response");
    const session: z.infer<typeof activeSchema> = {
      version: 1,
      phase: "active",
      authSession: parsed.data.auth_session ?? authSession,
      refreshToken: parsed.data.refresh_token ?? null,
      scopes: granted,
      account,
    };
    issuedCandidates.set(tx, {
      identity: { ...identity },
      accessToken: parsed.data.access_token,
    });
    return {
      session,
      token: {
        token: parsed.data.access_token,
        expiresAt: Math.min(
          parsed.data.expires_at * 1000,
          Date.now() + parsed.data.expires_in * 1000,
        ),
        refreshToken: session.refreshToken,
        authSession: session.authSession,
      },
    };
  }
  async function interaction(
    tx: SlotTransaction,
    identity: NativeIdentity,
    pending: Omit<Pending, "authSession" | "step">,
    form: URLSearchParams,
  ) {
    const response = await post(
      tx,
      identity,
      "/first-party/authorization-challenge",
      form,
    );
    if (response.status === 200) {
      const parsed = z
        .strictObject({
          authorization_code: capability,
          auth_session: capability,
        })
        .safeParse(response.body);
      if (!parsed.success) throw new FirstPartyClientError("invalid_response");
      return tokens(
        tx,
        identity,
        new URLSearchParams({
          grant_type: "authorization_code",
          client_id: config.clientId,
          code: parsed.data.authorization_code,
          code_verifier: pending.verifier,
        }),
        parsed.data.auth_session,
      );
    }
    if (response.status !== 403)
      throw new FirstPartyClientError("request_failed");
    const parsed = z
      .strictObject({
        error: z.literal("insufficient_authorization"),
        auth_session: capability,
        step: stepSchema,
        binding: bindingSchema.optional(),
        failure: z
          .enum(["invalid_credentials", "temporarily_unavailable"])
          .optional(),
      })
      .safeParse(response.body);
    if (!parsed.success) throw new FirstPartyClientError("unsupported_step");
    if (
      parsed.data.binding &&
      JSON.stringify(parsed.data.binding) !==
        JSON.stringify(bindingSchema.parse(pending.binding))
    )
      throw new FirstPartyClientError("invalid_response");
    const session: Pending = {
      ...pending,
      authSession: parsed.data.auth_session,
      step: parsed.data.step,
      ...(parsed.data.failure ? { failure: parsed.data.failure } : {}),
    };
    if (session.previousActive && session.sharesSession)
      session.previousActive = {
        ...session.previousActive,
        authSession: session.authSession,
      };
    // A previous invalid-password indication must not survive a successful step.
    if (!parsed.data.failure) delete session.failure;
    if (response.retryAt) session.retryAt = response.retryAt;
    else delete session.retryAt;
    return { session, token: undefined };
  }
  const basic = (authSession?: string) =>
    new URLSearchParams({
      profile: PROFILE,
      client_id: config.clientId,
      ...(authSession ? { auth_session: authSession } : {}),
    });
  async function initialize(slot: string, signal?: AbortSignal) {
    await run(
      slot,
      async (tx) => {
        const stored = read(tx);
        const identity =
          stored.identity ??
          identitySchema.parse(
            await ports.keys.prepare(slot, { signal: tx.signal }),
          );
        if (identity.retired || identity.superseded)
          throw new FirstPartyClientError("reauthentication_required");
        await ports.keys.assertAvailable(identity);
        return { identity, session: stored.session, result: undefined };
      },
      signal,
      true,
    );
  }
  function admissionContext(tx: SlotTransaction, identity: NativeIdentity) {
    return {
      signal: tx.signal,
      async saveIdentity(next: NativeIdentity) {
        const parsed = identitySchema.safeParse(next);
        if (!parsed.success) throw new FirstPartyClientError("invalid_state");
        const { providerRegistration: before, ...oldKey } = identity;
        const { providerRegistration: after, ...newKey } = parsed.data;
        if (
          JSON.stringify(oldKey) !== JSON.stringify(newKey) ||
          !(
            after === before ||
            after === "registered" ||
            (before === "generated" && after === "attesting")
          )
        )
          throw new FirstPartyClientError("invalid_state");
        await tx.saveIdentity(parsed.data);
        // Keep final commit consistent with durable progress, including when the
        // provider returns a fresh object instead of mutating its input.
        Object.assign(identity, parsed.data);
      },
    };
  }
  type Outcome = Awaited<ReturnType<typeof interaction>>;
  type Active = z.infer<typeof activeSchema>;
  function cachedAccess(slot: string, session: Active) {
    const cached = access.get(slot);
    return cached &&
      cached.expiresAt > Date.now() + 1000 &&
      cached.refreshToken === session.refreshToken &&
      cached.authSession === session.authSession
      ? cached
      : undefined;
  }
  async function refresh(
    tx: SlotTransaction,
    identity: NativeIdentity,
    session: Active,
  ) {
    if (!session.refreshToken)
      throw new FirstPartyClientError("reauthentication_required");
    const next = await tokens(
      tx,
      identity,
      new URLSearchParams({
        grant_type: "refresh_token",
        client_id: config.clientId,
        refresh_token: session.refreshToken,
      }),
      session.authSession,
    );
    if (next.session.refreshToken === session.refreshToken)
      throw new FirstPartyClientError("invalid_response");
    if (session.detachedInteraction) next.session.detachedInteraction = true;
    return next;
  }
  function resourceRequest(url: string, input: ResourceRequest) {
    try {
      const target = new URL(url);
      if (
        url.length > 8192 ||
        target.username ||
        target.password ||
        target.hash ||
        !allowedOrigins.has(target.origin) ||
        (target.protocol !== "https:" &&
          !(
            config.allowInsecureLoopback &&
            target.protocol === "http:" &&
            ["localhost", "127.0.0.1", "[::1]"].includes(target.hostname)
          ))
      )
        throw new Error();
      const method = z
        .enum(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
        .parse(input.method ?? "GET");
      const body = input.body ?? null;
      if (
        body !== null &&
        (typeof body !== "string" ||
          ["GET", "HEAD"].includes(method) ||
          new TextEncoder().encode(body).byteLength > 2_097_152)
      )
        throw new Error();
      const limit = z
        .number()
        .int()
        .min(1)
        .max(1_048_576)
        .parse(input.maximumResponseBytes ?? 1_048_576);
      const headers: Record<string, string> = {};
      for (const [key, value] of Object.entries(input.headers ?? {})) {
        const name = key.toLowerCase();
        if (
          !/^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(name) ||
          name in headers ||
          [
            "authorization",
            "dpop",
            "cookie",
            "cookie2",
            "host",
            "proxy-authorization",
            "connection",
            "transfer-encoding",
            "content-length",
          ].includes(name) ||
          typeof value !== "string" ||
          Array.from(value).some(
            (character) =>
              character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127,
          )
        )
          throw new Error();
        headers[name] = value;
      }
      if (new TextEncoder().encode(JSON.stringify(headers)).byteLength > 8192)
        throw new Error();
      return {
        url: target.href,
        method,
        body,
        headers,
        maximumResponseBytes: limit,
      };
    } catch {
      throw new FirstPartyClientError("invalid_request");
    }
  }
  async function protectedRequest(
    tx: Pick<SlotTransaction, "checkpoint" | "signal">,
    identity: NativeIdentity,
    token: string,
    request: ReturnType<typeof resourceRequest>,
  ): Promise<ResourceResponse> {
    const response = await signedRequest(
      tx,
      identity,
      {
        ...request,
        headers: {
          ...request.headers,
          Authorization: `DPoP ${token}`,
        },
      },
      token,
    );
    return { ...response, headers: response.headers ?? {} };
  }
  const finish = (slot: string, outcome: Outcome) => {
    if (outcome.token) access.set(slot, outcome.token);
    else access.delete(slot);
    return state(slot, outcome.session);
  };
  async function terminate(
    slot: string,
    action: "logout" | "retire",
    signal?: AbortSignal,
  ): Promise<TerminationResult> {
    browsers.get(slot)?.abort();
    cancellations.set(slot, {});
    const cached = access.get(slot);
    access.delete(slot);
    const unconfirmed: TerminationResult = {
      kind: "signed-out",
      slotId: slot,
      remote: "unconfirmed",
      keys: "retained",
    };
    try {
      return await run<TerminationResult>(
        slot,
        async (tx) => {
          const { identity, session } = read(tx);
          // This write keeps the lease, but removes durable capabilities before
          // any network or native-key availability check that can fail or hang.
          await tx.clearSession();
          const signedOut = (result: TerminationResult) => ({
            identity,
            session: null,
            result,
          });
          if (!identity) return signedOut(unconfirmed);
          const remove = async () => {
            await tx.checkpoint();
            try {
              await ports.keys.remove(identity);
              await tx.checkpoint();
              identity.keysRemoved = true;
              return signedOut({
                ...unconfirmed,
                remote: "confirmed",
                keys: "removed",
              });
            } catch {
              return signedOut({
                ...unconfirmed,
                remote: "confirmed",
                keys: "removal-pending",
              });
            }
          };
          // A previous response was durably confirmed, but deletion/commit may
          // have been interrupted. Retrying removal never needs old credentials.
          if (identity.retired)
            return action === "retire"
              ? remove()
              : signedOut({ ...unconfirmed, remote: "confirmed" });
          const active = activeSession(session);
          if (!active) return signedOut(unconfirmed);
          let confirmed = false;
          try {
            await ports.keys.assertAvailable(identity);
            const token =
              cached &&
              cached.expiresAt > Date.now() + 1000 &&
              cached.refreshToken === active.refreshToken &&
              cached.authSession === active.authSession
                ? cached.token
                : (await refresh(tx, identity, active)).token.token;
            const request = resourceRequest(`${issuer}/first-party/${action}`, {
              method: "POST",
              body: "{}",
              headers: {
                "Content-Type": "application/json",
                Accept: "application/json",
              },
              maximumResponseBytes: 65536,
            });
            const response = await protectedRequest(
              tx,
              identity,
              token,
              request,
            );
            confirmed =
              response.status === 200 &&
              z
                .strictObject({ success: z.literal(true) })
                .safeParse(JSON.parse(response.body) as unknown).success;
          } catch {
            /* Local sign-out succeeds independently; remote completion remains unconfirmed. */
          }
          if (!confirmed) return signedOut(unconfirmed);
          if (action === "logout")
            return signedOut({ ...unconfirmed, remote: "confirmed" });
          // Persist the server's result before removing either key. This record
          // permanently prevents this slot from preparing a replacement identity.
          const retired = { ...identity, retired: true as const };
          await tx.saveIdentity(retired);
          Object.assign(identity, retired);
          return remove();
        },
        signal,
      );
    } catch (error) {
      if (
        error instanceof FirstPartyClientError &&
        error.code === "vault_busy"
      ) {
        // Sign-out preempts a login/refresh already owning this slot. Its token
        // outcome is uncertain, so do not claim remote revocation.
        await coordinator.invalidate(slot);
        return unconfirmed;
      }
      if (
        error instanceof FirstPartyClientError &&
        error.code === "cancelled" &&
        error.cleanup === "complete"
      )
        return unconfirmed;
      throw error;
    }
  }
  return {
    readIdentity(slot: string): Promise<NativeIdentity | null> {
      return run(
        slot,
        (tx) => {
          tx.readOnly();
          const { identity, session } = read(tx);
          return Promise.resolve({ identity, session, result: identity });
        },
        undefined,
        true,
      );
    },
    /** Import contains only native-read references. No old session or asserted
     * account identity is accepted, and no missing key may be generated here. */
    installRetainedIdentity(
      slot: string,
      input: RetainedIOSIdentity,
    ): Promise<void> {
      const parsed = retainedIOSIdentitySchema.safeParse(input);
      if (!parsed.success) throw new FirstPartyClientError("invalid_request");
      return run(
        slot,
        async (tx) => {
          const stored = read(tx);
          if (stored.identity) {
            const existing = stored.identity;
            if (
              existing.retired ||
              existing.superseded ||
              existing.dpopAlias !== parsed.data.dpopAlias ||
              existing.dpopJkt !== parsed.data.dpopJkt ||
              existing.providerKeyId !== parsed.data.providerKeyId ||
              existing.providerScope !== parsed.data.providerScope ||
              existing.providerStoragePrefix !==
                parsed.data.providerStoragePrefix
            )
              throw new FirstPartyClientError("invalid_state");
            tx.readOnly();
            await ports.keys.assertAvailable(existing);
            return { ...stored, result: undefined };
          }
          if (stored.session) throw new FirstPartyClientError("vault_corrupt");
          await ports.keys.assertAvailable(parsed.data);
          return { identity: parsed.data, session: null, result: undefined };
        },
        undefined,
        true,
      );
    },
    /** Local metadata only: no refresh, network, key generation, or key deletion. */
    inspect(slot: string): Promise<AccountSlot> {
      return run(
        slot,
        (tx) => {
          tx.readOnly();
          const { identity, session } = read(tx);
          return Promise.resolve({
            identity,
            session,
            result: {
              slotId: slot,
              status: identity?.retired
                ? "retired"
                : identity?.superseded
                  ? "recovery-required"
                  : identity?.account
                    ? "saved"
                    : "pending",
              ...(identity?.account ? { account: identity.account } : {}),
              hasSession: Boolean(activeSession(session)),
              hasInteraction: session?.phase === "interaction",
              keysRemoved: identity?.keysRemoved === true,
            } satisfies AccountSlot,
          });
        },
        undefined,
        true,
      );
    },
    /** Explicit recovery fences this slot locally. It does not revoke or delete
     * its keys, and cannot transfer authority to the catalog's replacement. */
    async beginRecovery(slot: string, allowEmptyImport = false): Promise<void> {
      browsers.get(slot)?.abort();
      cancellations.set(slot, {});
      access.delete(slot);
      await coordinator.invalidate(slot);
      await run(slot, (tx) => {
        const { identity } = read(tx);
        if (!identity && allowEmptyImport)
          return Promise.resolve({
            identity: null,
            session: null,
            result: undefined,
          });
        if (!identity || identity.retired)
          throw new FirstPartyClientError("invalid_state");
        return Promise.resolve({
          identity: { ...identity, superseded: true as const },
          session: null,
          result: undefined,
        });
      });
    },
    logout: (slot: string, signal?: AbortSignal) =>
      terminate(slot, "logout", signal),
    retire: (slot: string, signal?: AbortSignal) =>
      terminate(slot, "retire", signal),
    async openBrowser(
      slot: string,
      input: { flowId: string; stepId: string },
      signal?: AbortSignal,
    ): Promise<ClientState> {
      if (!redirectUri || !ports.browser)
        throw new FirstPartyClientError("browser_unavailable");
      if (browsers.has(slot)) throw new FirstPartyClientError("browser_busy");
      const version = cancellations.get(slot);
      const prepared = await run(
        slot,
        async (tx) => {
          const { identity, session } = await requireIdentity(tx);
          if (
            session?.phase !== "interaction" ||
            session.flowId !== input.flowId ||
            session.step.id !== input.stepId ||
            session.step.kind !== "browser-required" ||
            session.browser
          )
            return { identity, session, result: null };
          const stateToken = digest.parse(
            (await ports.crypto.transaction()).id,
          );
          const form = basic(session.authSession);
          form.set("step_id", session.step.id);
          form.set(
            "response",
            JSON.stringify({ kind: "browser", state: stateToken, redirectUri }),
          );
          const response = await post(
            tx,
            identity,
            "/first-party/authorization-challenge",
            form,
          );
          const parsed = z
            .strictObject({
              error: z.literal("redirect_to_web"),
              auth_session: capability,
              request_uri: z
                .string()
                .regex(
                  /^urn:ietf:params:oauth:request_uri:fpb1_[A-Za-z0-9_-]{43}$/,
                ),
              expires_in: z.number().int().min(1).max(300),
              step: z.strictObject({
                kind: z.literal("browser-required"),
                id: identifier,
              }),
            })
            .safeParse(response.body);
          if (response.status !== 403 || !parsed.success)
            throw new FirstPartyClientError("invalid_response");
          const pending: Pending = {
            ...session,
            authSession: parsed.data.auth_session,
            step: parsed.data.step,
            browser: {
              state: stateToken,
              requestUri: parsed.data.request_uri,
              redirectUri,
              expiresAt: Date.now() + parsed.data.expires_in * 1000,
            },
          };
          if (pending.previousActive && pending.sharesSession)
            pending.previousActive = {
              ...pending.previousActive,
              authSession: pending.authSession,
            };
          return { identity, session: pending, result: pending };
        },
        signal,
        true,
      );
      if (!prepared?.browser) throw new FirstPartyClientError("invalid_state");
      ensureCurrent(slot, version, signal);
      const controller = new AbortController();
      const abort = () => controller.abort();
      signal?.addEventListener("abort", abort, { once: true });
      browsers.set(slot, controller);
      try {
        const authorization = new URL(`${issuer}/oauth2/authorize`);
        authorization.searchParams.set("client_id", config.clientId);
        authorization.searchParams.set(
          "request_uri",
          prepared.browser.requestUri,
        );
        const callback = await ports.browser.open({
          url: authorization.href,
          redirectUri,
          timeoutMilliseconds: Math.max(
            1,
            prepared.browser.expiresAt - Date.now(),
          ),
          signal: controller.signal,
        });
        ensureCurrent(slot, version, controller.signal);
        const code = authorizationCallback(callback, {
          redirectUri,
          state: prepared.browser.state,
          issuer,
        });
        const outcome = await run<Outcome | null>(
          slot,
          async (tx) => {
            const { identity, session } = await requireIdentity(tx);
            if (
              session?.phase !== "interaction" ||
              session.flowId !== prepared.flowId ||
              session.browser?.state !== prepared.browser!.state ||
              session.step.id !== prepared.step.id
            )
              return { identity, session, result: null };
            if (session.browser.expiresAt <= Date.now())
              throw new FirstPartyClientError("reauthentication_required");
            const next = await tokens(
              tx,
              identity,
              new URLSearchParams({
                grant_type: "authorization_code",
                client_id: config.clientId,
                code,
                code_verifier: session.verifier,
                redirect_uri: session.browser.redirectUri,
              }),
              session.authSession,
            );
            return { identity, session: next.session, result: next };
          },
          controller.signal,
          true,
        );
        ensureCurrent(slot, version, controller.signal);
        if (!outcome) throw new FirstPartyClientError("invalid_state");
        return finish(slot, outcome);
      } catch (error) {
        if (error instanceof FirstPartyClientError) throw error;
        throw new FirstPartyClientError("browser_failed");
      } finally {
        signal?.removeEventListener("abort", abort);
        if (browsers.get(slot) === controller) browsers.delete(slot);
      }
    },
    async start(slot: string, signal?: AbortSignal): Promise<ClientState> {
      const version = cancellations.get(slot);
      access.delete(slot);
      await initialize(slot, signal);
      ensureCurrent(slot, version, signal);
      const outcome = await run(
        slot,
        async (tx) => {
          const { identity, session: prior } = await requireIdentity(tx);
          const transaction = z
            .strictObject({ id: digest, verifier: digest, challenge: digest })
            .parse(await ports.crypto.transaction());
          const binding: NativeBinding = {
            profile: PROFILE,
            mode: "native",
            issuer,
            clientId: config.clientId,
            applicationId: config.applicationId,
            provider: config.provider,
            environment: config.environment,
            attemptId: transaction.id,
            codeChallenge: transaction.challenge,
            codeChallengeMethod: "S256",
            dpopJkt: identity.dpopJkt,
            scopes,
            resources,
          };
          const grant = await ports.keys.admission(
            identity,
            binding,
            admissionContext(tx, identity),
          );
          const previousActive = activeSession(prior);
          const sharesSession =
            prior?.phase === "active" && !prior.detachedInteraction;
          const form = basic(sharesSession ? prior.authSession : undefined);
          for (const [key, value] of Object.entries({
            response_type: "code",
            scope: scopes.join(" "),
            code_challenge: binding.codeChallenge,
            code_challenge_method: "S256",
            authorization_attempt: binding.attemptId,
            device_attestation: capability.parse(grant),
          }))
            form.set(key, value);
          for (const resource of resources) form.append("resource", resource);
          const outcome = await interaction(
            tx,
            identity,
            {
              version: 1,
              phase: "interaction",
              flowId: transaction.id,
              verifier: transaction.verifier,
              binding,
              ...(previousActive ? { previousActive } : {}),
              ...(sharesSession ? { sharesSession: true as const } : {}),
            },
            form,
          );
          return { identity, session: outcome.session, result: outcome };
        },
        signal,
        true,
      );
      ensureCurrent(slot, version, signal);
      return finish(slot, outcome);
    },
    async respond(
      slot: string,
      input: {
        flowId: string;
        stepId: string;
        response:
          | { kind: "password"; email: string; password: string }
          | { kind: "email-otp-request"; email: string }
          | { kind: "email-otp-resend" }
          | { kind: "email-otp"; otp: string }
          | { kind: "attestation" };
      },
      signal?: AbortSignal,
    ): Promise<ClientState> {
      const version = cancellations.get(slot);
      const answer = z
        .discriminatedUnion("kind", [
          z.strictObject({
            kind: z.literal("password"),
            email: z.email().max(320),
            password: z.string().min(1).max(1024),
          }),
          z.strictObject({
            kind: z.literal("email-otp-request"),
            email: z.email().max(320),
          }),
          z.strictObject({ kind: z.literal("email-otp-resend") }),
          z.strictObject({
            kind: z.literal("email-otp"),
            otp: z.string().min(1).max(128),
          }),
          z.strictObject({ kind: z.literal("attestation") }),
        ])
        .safeParse(input.response);
      if (!answer.success) throw new FirstPartyClientError("invalid_state");
      const result = await run(
        slot,
        async (tx) => {
          const { identity, session } = await requireIdentity(tx);
          if (
            session?.phase !== "interaction" ||
            session.flowId !== input.flowId ||
            session.step.id !== input.stepId ||
            !(session.step.kind === "authentication"
              ? (answer.data.kind === "password" &&
                  session.step.methods.includes("password")) ||
                (answer.data.kind === "email-otp-request" &&
                  session.step.methods.includes("email-otp"))
              : session.step.kind === answer.data.kind ||
                (session.step.kind === "email-otp" &&
                  answer.data.kind === "email-otp-resend"))
          )
            return { identity, session, result: null };
          const response =
            answer.data.kind === "attestation"
              ? {
                  kind: "attestation",
                  grantToken: await ports.keys.admission(
                    identity,
                    session.binding,
                    admissionContext(tx, identity),
                  ),
                }
              : answer.data;
          const form = basic(session.authSession);
          form.set("step_id", session.step.id);
          form.set("response", JSON.stringify(response));
          const outcome = await interaction(tx, identity, session, form);
          return { identity, session: outcome.session, result: outcome };
        },
        signal,
        true,
      );
      if (!result) throw new FirstPartyClientError("invalid_state");
      ensureCurrent(slot, version, signal);
      return finish(slot, result);
    },
    async restore(slot: string, signal?: AbortSignal): Promise<ClientState> {
      const version = cancellations.get(slot);
      access.delete(slot);
      const outcome = await run<Outcome | null>(
        slot,
        async (tx) => {
          const { identity, session } = await requireIdentity(tx);
          if (!session) return { identity, session: null, result: null };
          if (session.phase === "interaction") {
            tx.readOnly();
            return { identity, session, result: { session, token: undefined } };
          }
          const next = await refresh(tx, identity, session);
          return { identity, session: next.session, result: next };
        },
        signal,
      );
      ensureCurrent(slot, version, signal);
      return outcome ? finish(slot, outcome) : state(slot, null);
    },
    /** Bounded text transport. The consumer owns application-level retries. */
    async fetch(
      slot: string,
      url: string,
      input: ResourceRequest = {},
    ): Promise<ResourceResponse> {
      // Validate before taking a lease so bad application input cannot sign out a valid account.
      const request = resourceRequest(url, input);
      const version = cancellations.get(slot);
      for (let attempt = 0; attempt < 3; attempt++) {
        ensureCurrent(slot, version, input.signal);
        type Result =
          | { kind: "refreshed"; token: NonNullable<Outcome["token"]> }
          | { kind: "response"; response: ResourceResponse }
          | { kind: "error"; error: FirstPartyClientError };
        const result = await run<Result>(
          slot,
          async (tx) => {
            const { identity, session } = await requireIdentity(tx);
            const active = activeSession(session);
            if (!active || !session)
              throw new FirstPartyClientError("reauthentication_required");
            const cached = cachedAccess(slot, active);
            if (!cached) {
              const next = await refresh(tx, identity, active);
              return {
                identity,
                session: replaceActive(session, next.session),
                result: { kind: "refreshed", token: next.token },
              };
            }
            try {
              tx.readOnly();
              const response = await protectedRequest(
                tx,
                identity,
                cached.token,
                request,
              );
              return {
                identity,
                session,
                result: { kind: "response", response },
              };
            } catch (error) {
              // A failed business request does not make an already committed refresh
              // uncertain. Persist the unchanged session, then surface a safe error.
              return {
                identity,
                session,
                result: {
                  kind: "error",
                  error:
                    error instanceof FirstPartyClientError
                      ? error
                      : new FirstPartyClientError("request_failed"),
                },
              };
            }
          },
          input.signal,
        );
        ensureCurrent(slot, version, input.signal);
        if (result.kind === "refreshed") {
          // Commit rotation before any application side effect. A second runtime
          // may rotate again; recheck its durable session before using this cache.
          access.set(slot, result.token);
          continue;
        }
        if (result.kind === "error") throw result.error;
        return result.response;
      }
      throw new FirstPartyClientError("vault_busy");
    },
    /** Cancel an interaction, preserving independently committed access. */
    async cancel(slot: string): Promise<ClientState> {
      browsers.get(slot)?.abort();
      cancellations.set(slot, {});
      access.delete(slot);
      const cancelled = await coordinator.cancelInteraction(slot);
      const prior = pendingSchema.safeParse(cancelled.session);
      return run(
        slot,
        async (tx) => {
          const { identity, session } = read(tx);
          // Another runtime can start a new interaction after native cancellation.
          // Do not alter it or apply an old continuation result to a new session.
          if (
            !identity ||
            session?.phase === "interaction" ||
            !prior.success ||
            (session?.refreshToken ?? null) !==
              (prior.data.previousActive?.refreshToken ?? null)
          )
            return { identity, session, result: state(slot, session) };
          let restored = session;
          try {
            await ports.keys.assertAvailable(identity);
            const form = basic(prior.data.authSession);
            form.set("step_id", prior.data.step.id);
            form.set("response", JSON.stringify({ kind: "cancel" }));
            const response = await post(
              tx,
              identity,
              "/first-party/authorization-challenge",
              form,
            );
            const parsed = z
              .strictObject({
                cancelled: z.literal(true),
                auth_session: capability,
              })
              .safeParse(response.body);
            if (
              response.status === 200 &&
              parsed.success &&
              restored &&
              prior.data.previousActive
            ) {
              restored = {
                ...restored,
                authSession: prior.data.sharesSession
                  ? parsed.data.auth_session
                  : prior.data.previousActive.authSession,
              };
              if (!prior.data.previousActive.detachedInteraction)
                delete restored.detachedInteraction;
            }
          } catch {
            /* The old access family remains independent; remote cancellation is best effort. */
          }
          return { identity, session: restored, result: state(slot, restored) };
        },
        undefined,
        true,
      );
    },
  };
}
