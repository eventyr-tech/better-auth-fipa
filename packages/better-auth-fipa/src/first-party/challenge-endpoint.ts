import {
  createDpopProofError,
  deriveDpopJkt,
  isDpopProofError,
} from "@better-auth/core/oauth2";
import { APIError, createAuthEndpoint } from "better-auth/api";
import { z } from "zod";
import { DeviceAttestationError } from "../errors.js";
import type { NativeTokenOptions } from "./token-lifecycle.js";
import { prepareNativeBrowser } from "./browser.js";
import { nativeAdmissionBindingSchema } from "./admission-binding.js";
import {
  AUTHORIZATION_CHALLENGE_PATH,
  startNativeAuthorization,
  submitNativePassword,
  submitNativeEmailOTP,
  renewNativeEvidence,
  cancelNativeAttempt,
  validateContinuationPolicy,
  type NativeInteraction,
} from "./continuation.js";
import { requestNativeEmailOTP } from "./email-otp-continuation.js";
import { validateEmailDeliveryPolicy } from "./email-otp-delivery.js";
import { FIRST_PARTY_PROFILE, parseFirstPartyWireRequest } from "./wire.js";
import type { GenericEndpointContext } from "@better-auth/core";
import {
  parseLegacyChallenge,
  type LegacyChallengeRequest,
  type LegacyClientPolicy,
} from "./legacy-v1/contract.js";

/** Internal seam for the reusable legacy adapter. Public configuration supplies
 * policy, never a consumer callback that bypasses the protocol coordinator. */
export interface LegacyChallengeAdapter {
  policies: readonly LegacyClientPolicy[];
  handle(
    ctx: GenericEndpointContext,
    request: LegacyChallengeRequest,
    policy: LegacyClientPolicy,
  ): Promise<Response>;
}

const common = {
  profile: z.literal(FIRST_PARTY_PROFILE),
  client_id: z.string().min(1).max(256),
  dpop_jkt: z.string().optional(),
};
const initial = z.strictObject({
  ...common,
  response_type: z.literal("code"),
  scope: z.string(),
  resource: z.array(z.string()).optional(),
  code_challenge: z.string(),
  code_challenge_method: z.literal("S256"),
  authorization_attempt: z.string(),
  device_attestation: z.string(),
  auth_session: z.string().optional(),
  nonce: z.string().optional(),
  acr_values: z.string().optional(),
  max_age: z.string().regex(/^\d+$/).optional(),
  login_hint: z.string().max(320).optional(),
});
const continuation = z.strictObject({
  ...common,
  auth_session: z.string(),
  step_id: z.string(),
  response: z.string().max(4096),
});
const answer = z.discriminatedUnion("kind", [
  z.strictObject({
    kind: z.literal("password"),
    email: z.email().max(320),
    password: z.string().min(1).max(1024),
  }),
  z.strictObject({
    kind: z.literal("attestation"),
    grantToken: z.string().max(128),
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
  z.strictObject({ kind: z.literal("cancel") }),
  z.strictObject({
    kind: z.literal("browser"),
    redirectUri: z.string().max(2048),
    state: z.string().max(128),
  }),
]);

/** One route owner; protocol selection is completed before either adapter runs. */
export function createNativeChallengeEndpoint(
  options: NativeTokenOptions,
  legacy?: LegacyChallengeAdapter,
) {
  validateContinuationPolicy(options.lifetimes);
  if (options.emailOTP) validateEmailDeliveryPolicy(options.emailOTP);
  const clients = new Map(
    options.applications.map((application) => [
      application.clientId,
      application,
    ]),
  );
  if (clients.size !== options.applications.length)
    throw new TypeError(
      "Native client IDs must select exactly one application policy.",
    );
  const legacyClients = new Map(
    legacy?.policies.map((policy) => [policy.clientId, policy]),
  );
  if (
    legacy &&
    (!legacyClients.size ||
      legacyClients.size !== legacy.policies.length ||
      [...legacyClients.keys()].some((id) => !clients.has(id)))
  )
    throw new TypeError(
      "Legacy compatibility requires unique, explicitly configured native client IDs.",
    );
  return createAuthEndpoint(
    AUTHORIZATION_CHALLENGE_PATH,
    {
      method: "POST",
      disableBody: true,
      requireRequest: true,
    },
    async (ctx) => {
      ctx.setHeader("Cache-Control", "no-store");
      try {
        const parsed = await parseFirstPartyWireRequest(ctx.request, {
          legacyEnabled: !!legacy,
        });
        const parameters = parsed.parameters;
        if (parsed.protocol === "legacy-v1") {
          const policy =
            typeof parameters.client_id === "string"
              ? legacyClients.get(parameters.client_id)
              : undefined;
          // Submitted clients do not send a proof here. Mixed requests cannot
          // shed a failed proof and be retried as an unproven legacy request.
          if (!legacy || !policy || ctx.request.headers.has("dpop"))
            throw invalidRequest();
          const validated = parseLegacyChallenge(parameters, policy);
          return legacy.handle(ctx, validated.request, policy);
        }
        const application =
          typeof parameters.client_id === "string"
            ? clients.get(parameters.client_id)
            : undefined;
        if (!application)
          throw new APIError("BAD_REQUEST", { error: "invalid_client" });
        let result: NativeInteraction;
        if (Object.hasOwn(parameters, "device_attestation")) {
          const request = initial.safeParse(parameters);
          if (!request.success) throw invalidRequest();
          const fields = request.data;
          // This extracts a candidate only. startNativeAuthorization verifies the
          // signature, request URL, freshness, replay and exact attestation binding.
          const jkt = await candidateThumbprint(ctx.request.headers);
          if (fields.dpop_jkt !== undefined && fields.dpop_jkt !== jkt)
            throw invalidRequest();
          // No configured ACR mapping exists yet; never silently claim one was met.
          if (fields.acr_values?.trim()) throw invalidRequest();
          const binding = nativeAdmissionBindingSchema.safeParse({
            profile: FIRST_PARTY_PROFILE,
            mode: "native",
            issuer: ctx.context.baseURL,
            clientId: application.clientId,
            provider: application.provider.id,
            applicationId: application.applicationId,
            environment: application.environment,
            attemptId: fields.authorization_attempt,
            dpopJkt: jkt,
            codeChallenge: fields.code_challenge,
            codeChallengeMethod: fields.code_challenge_method,
            scopes: fields.scope.split(" "),
            resources: fields.resource ?? [],
            ...(fields.nonce === undefined ? {} : { nonce: fields.nonce }),
            ...(fields.max_age === undefined
              ? {}
              : { maxAge: Number(fields.max_age) }),
          });
          if (!binding.success) throw invalidRequest();
          result = await startNativeAuthorization(
            ctx,
            application,
            options.lifetimes,
            {
              binding: binding.data,
              grantToken: fields.device_attestation,
              headers: ctx.request.headers,
              ...(options.emailOTP
                ? {
                    methods: [
                      ...(ctx.context.options.emailAndPassword?.enabled
                        ? ["password" as const]
                        : []),
                      "email-otp" as const,
                    ],
                  }
                : {}),
              ...(fields.auth_session === undefined
                ? {}
                : { authSession: fields.auth_session }),
            },
          );
        } else {
          const request = continuation.safeParse(parameters);
          if (!request.success) throw invalidRequest();
          const fields = request.data;
          let decoded: unknown;
          try {
            decoded = JSON.parse(fields.response);
          } catch {
            throw invalidRequest();
          }
          const response = answer.safeParse(decoded);
          if (!response.success) throw invalidRequest();
          if (
            fields.dpop_jkt !== undefined &&
            fields.dpop_jkt !== (await candidateThumbprint(ctx.request.headers))
          )
            throw invalidRequest();
          const input = {
            authSession: fields.auth_session,
            clientId: application.clientId,
            stepId: fields.step_id,
            headers: ctx.request.headers,
          };
          if (response.data.kind === "password")
            result = await submitNativePassword(ctx, options.lifetimes, {
              ...input,
              response: {
                email: response.data.email,
                password: response.data.password,
              },
            });
          else if (
            response.data.kind === "email-otp-request" ||
            response.data.kind === "email-otp-resend"
          )
            result = await requestNativeEmailOTP(ctx, options, {
              ...input,
              ...(response.data.kind === "email-otp-request"
                ? { email: response.data.email }
                : {}),
            });
          else if (response.data.kind === "email-otp") {
            if (!options.emailOTP) throw invalidRequest();
            result = await submitNativeEmailOTP(ctx, options.lifetimes, {
              ...input,
              otp: response.data.otp,
            });
          } else if (response.data.kind === "attestation")
            result = await renewNativeEvidence(
              ctx,
              application,
              options.lifetimes,
              { ...input, grantToken: response.data.grantToken },
            );
          else if (response.data.kind === "browser")
            result = await prepareNativeBrowser(ctx, options, {
              ...input,
              redirectUri: response.data.redirectUri,
              state: response.data.state,
            });
          else
            result = await cancelNativeAttempt(ctx, options.lifetimes, input);
        }
        if (result.kind === "authorized")
          return ctx.json({
            authorization_code: result.authorizationCode,
            auth_session: result.authSession,
          });
        if (result.kind === "cancelled")
          return ctx.json({
            cancelled: true,
            auth_session: result.authSession,
          });
        if (result.kind === "step" && result.retryAfter)
          ctx.setHeader("Retry-After", result.retryAfter);
        ctx.setStatus(403);
        if (result.kind === "browser")
          return ctx.json(
            {
              error: "redirect_to_web",
              auth_session: result.authSession,
              request_uri: result.requestUri,
              expires_in: result.expiresIn,
              step: { kind: "browser-required", id: result.stepId },
            },
            { status: 403 },
          );
        return ctx.json(
          {
            error: "insufficient_authorization",
            auth_session: result.authSession,
            step: result.step,
            ...(result.binding ? { binding: result.binding } : {}),
            ...(result.failure ? { failure: result.failure } : {}),
          },
          { status: 403 },
        );
      } catch (error) {
        if (isDpopProofError(error))
          throw new APIError("BAD_REQUEST", { error: error.code });
        if (error instanceof DeviceAttestationError)
          throw new APIError("BAD_REQUEST", {
            error: "invalid_request",
            code: error.code,
          });
        throw error;
      }
    },
  );
}

async function candidateThumbprint(headers: Headers): Promise<string> {
  try {
    const proof = headers.get("dpop");
    if (!proof || proof.length > 8192) throw new Error();
    const parts = proof.split(".");
    if (parts.length !== 3 || !parts[0]) throw new Error();
    const header = z
      .object({
        jwk: z.object({
          kty: z.literal("EC"),
          crv: z.literal("P-256"),
          x: z.string(),
          y: z.string(),
        }),
      })
      .parse(
        JSON.parse(
          Buffer.from(parts[0], "base64url").toString("utf8"),
        ) as unknown,
      );
    return await deriveDpopJkt(header.jwk);
  } catch {
    throw createDpopProofError(
      "invalid_dpop_proof",
      "A bounded ES256 proof is required.",
    );
  }
}
function invalidRequest(): APIError {
  return new APIError("BAD_REQUEST", { error: "invalid_request" });
}
