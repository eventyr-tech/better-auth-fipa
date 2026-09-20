import { DatabaseSync } from "node:sqlite";
import {
  betterAuth,
  type BetterAuthOptions,
  type BetterAuthPlugin,
} from "better-auth";
import { emailOTP, twoFactor } from "better-auth/plugins";
import { createAuthEndpoint } from "better-auth/api";
import { getMigrations } from "better-auth/db/migration";
import { oauthProvider, type OAuthOptions } from "@better-auth/oauth-provider";
import {
  appAttest,
  createDeviceAttestation,
  type DeviceAttestationProvider,
} from "@eventyr-tech/better-auth-fipa";
import {
  createNativeFirstPartyPlugin,
  androidHardware,
  type AndroidHardwareOptions,
  requireNativeAccess,
  resolveFirstPartyTokenContext,
  type NativeTokenOptions,
} from "@eventyr-tech/better-auth-fipa/first-party";
import { loginPage } from "./login-page.js";

export const EXAMPLE_CLIENT_ID = "example-mobile";
export const EXAMPLE_ANDROID_CLIENT_ID = "example-android";
export const EXAMPLE_CALLBACK = "com.example.deviceattestation:/auth/callback";
export const EXAMPLE_SCOPES = ["example:read", "offline_access"];

/** Local device-test server. Its database and secret must survive restarts. */
export async function createExampleServer(options: {
  baseURL: string;
  applicationId: string;
  secret: string;
  environment: "development" | "production";
  database: DatabaseSync;
  /** Runs the dedicated Android example instead of App Attest. */
  android?: AndroidHardwareOptions;
  /** Bootstraps this account once, before accepting HTTP requests. Never resets a password. */
  seedAccount?: { email: string; password: string; name: string };
  /** Test-only evidence seam. The executable always uses real platform verification. */
  provider?: DeviceAttestationProvider;
  /** Optional host-owned delivery. The library never logs or returns codes to the app. */
  sendTwoFactorOTP?: (input: { email: string; otp: string }) => Promise<void>;
  sendEmailOTP?: (input: { email: string; otp: string }) => Promise<void>;
}) {
  const origin = new URL(options.baseURL).origin;
  if (options.baseURL !== origin || options.secret.length < 32)
    throw new TypeError(
      "Use an origin base URL and a persistent secret of at least 32 characters.",
    );
  if (
    options.android &&
    (options.provider ||
      options.environment !== "production" ||
      options.applicationId !== options.android.key.packageName)
  )
    throw new TypeError(
      "Android requires matching production application policy and no Apple provider override.",
    );
  const clientId = options.android
    ? EXAMPLE_ANDROID_CLIENT_ID
    : EXAMPLE_CLIENT_ID;
  const apple = options.android
    ? undefined
    : (options.provider ??
      appAttest({
        applications: [
          {
            appId: options.applicationId,
            platform: "ios",
            environment: options.environment,
          },
        ],
      }));
  const provider = options.android ? androidHardware(options.android) : apple!;
  const low = apple
    ? createDeviceAttestation({
        providers: [apple],
        purposes: {
          credentialRegistration: {
            maxActiveUnboundCredentialsPerApplication: 20,
          },
          oauthAuthorization: {
            protectedClientIds: [clientId],
            requireDpopJkt: true,
          },
        },
      })
    : undefined;
  const oauthOptions: OAuthOptions<string[]> = {
    loginPage: "/login",
    consentPage: "/login",
    disableJwtPlugin: true,
    scopes: EXAMPLE_SCOPES,
    grantTypes: ["authorization_code", "refresh_token"],
    allowDynamicClientRegistration: false,
    allowUnauthenticatedClientRegistration: false,
    customAccessTokenClaims: async (info) => {
      const context = await resolveFirstPartyTokenContext(native, info);
      if (!context)
        throw new Error("The example requires a first-party token family.");
      return {
        "urn:example:first-party:profile": context.profile,
        "urn:example:first-party:auth_time": context.authTime,
        "urn:example:first-party:family": context.familyId,
      };
    },
  };
  const native: NativeTokenOptions = {
    ...(options.sendEmailOTP
      ? {
          emailOTP: {
            recipient: {
              maxRequests: 5,
              windowSeconds: 3600,
              minimumIntervalSeconds: 60,
            },
            credential: {
              maxRequests: 10,
              windowSeconds: 3600,
              minimumIntervalSeconds: 10,
            },
          },
        }
      : {}),
    oauth: oauthOptions,
    browser: { loginPage: "/login" },
    applications: [
      {
        clientId,
        provider,
        applicationId: options.applicationId,
        environment: options.environment,
        scopes: EXAMPLE_SCOPES,
        resources: [],
      },
    ],
    lifetimes: {
      sessionIdleSeconds: 3600,
      sessionAbsoluteSeconds: 86400,
      familyLifetimeSeconds: 86400,
      evidenceMaxAgeSeconds: 300,
    },
    accessTokenSeconds: 300,
    maximumAssuranceAgeSeconds: 86400,
  };
  const oauth = oauthProvider(oauthOptions);
  // BA 1.7.5's inferred provider endpoint union needs this structural annotation.
  const oauthPlugin: BetterAuthPlugin = {
    ...oauth,
    endpoints: oauth.endpoints as unknown as NonNullable<
      BetterAuthPlugin["endpoints"]
    >,
  };
  const authOptions = {
    baseURL: origin,
    secret: options.secret,
    database: options.database,
    emailAndPassword: { enabled: true, disableSignUp: true },
    trustedOrigins: [origin],
    plugins: [
      ...(low ? [low.serverPlugin] : []),
      ...(options.sendEmailOTP
        ? [
            emailOTP({
              storeOTP: "hashed",
              disableSignUp: true,
              expiresIn: 300,
              sendVerificationOTP: options.sendEmailOTP,
            }) as BetterAuthPlugin,
          ]
        : []),
      ...(options.sendTwoFactorOTP
        ? [
            twoFactor({
              otpOptions: {
                sendOTP: ({ user, otp }) =>
                  options.sendTwoFactorOTP!({ email: user.email, otp }),
              },
            }) as BetterAuthPlugin,
          ]
        : []),
      oauthPlugin,
      createNativeFirstPartyPlugin(native),
      {
        id: "example-resource",
        endpoints: {
          exampleAccount: createAuthEndpoint(
            "/example/account",
            { method: "GET", requireHeaders: true },
            async (ctx) => {
              const principal = await requireNativeAccess(ctx, native, {
                headers: ctx.headers,
                method: "GET",
                url: `${ctx.context.baseURL}/example/account`,
                scopes: ["example:read"],
              });
              ctx.setHeader("Cache-Control", "no-store");
              return ctx.json({
                subject: principal.userId,
                credentialId: principal.credentialId,
                assurance: principal.assurance,
              });
            },
          ),
        },
      },
    ],
  } satisfies BetterAuthOptions;
  // Automatic migrations are appropriate only for this dedicated example database.
  await (await getMigrations(authOptions)).runMigrations();
  const auth = betterAuth(authOptions);
  const context = await auth.$context;
  const existing = await context.adapter.findOne<{
    clientId: string;
    tokenEndpointAuthMethod: string;
    redirectUris: string[];
    grantTypes: string[];
    scopes: string[];
    disabled: boolean | null;
  }>({
    model: "oauthClient",
    where: [{ field: "clientId", value: clientId }],
  });
  if (existing) {
    const same = (a: string[], b: string[]) =>
      JSON.stringify([...a].sort()) === JSON.stringify([...b].sort());
    if (
      existing.tokenEndpointAuthMethod !== "none" ||
      existing.disabled ||
      !same(existing.redirectUris, [EXAMPLE_CALLBACK]) ||
      !same(existing.grantTypes, ["authorization_code", "refresh_token"]) ||
      !same(existing.scopes, EXAMPLE_SCOPES)
    )
      throw new Error(
        "The saved example OAuth client differs from the configured native client.",
      );
  } else {
    await context.adapter.create({
      model: "oauthClient",
      data: {
        clientId,
        redirectUris: [EXAMPLE_CALLBACK],
        tokenEndpointAuthMethod: "none",
        grantTypes: ["authorization_code", "refresh_token"],
        scopes: EXAMPLE_SCOPES,
        disabled: false,
      },
    });
  }
  if (
    options.seedAccount &&
    !(await context.internalAdapter.findUserByEmail(options.seedAccount.email))
  ) {
    // Use the same public sign-up pipeline during bootstrap only. HTTP sign-up stays disabled.
    const bootstrap = betterAuth({
      ...auth.options,
      plugins: [],
      emailAndPassword: { enabled: true, disableSignUp: false },
    });
    const registered = await bootstrap.api.signUpEmail({
      body: options.seedAccount,
    });
    if (registered.token)
      await context.internalAdapter.deleteSession(registered.token);
  }
  return {
    async handler(request: Request): Promise<Response> {
      const url = new URL(request.url);
      if (url.origin !== origin)
        return Response.json({ error: "invalid_origin" }, { status: 400 });
      if (request.method === "GET" && url.pathname === "/login")
        return loginPage(origin);
      if (url.pathname.startsWith("/api/auth/")) return auth.handler(request);
      return Response.json({ error: "not_found" }, { status: 404 });
    },
  };
}
