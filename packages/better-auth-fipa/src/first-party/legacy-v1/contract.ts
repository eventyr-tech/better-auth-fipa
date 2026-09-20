import { APIError } from "better-auth/api";
import { z } from "zod";
import { normalizeOAuthBinding } from "../../protocol/binding.js";
import type { OAuthAuthorizationBinding } from "../../types.js";

const digest = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
const text = z.string().min(1).max(256);
export const legacyStepSchema = z.enum([
  "email_password",
  "email_verification",
  "profile_password",
  "organization_details",
]);
export type LegacyStep = z.infer<typeof legacyStepSchema>;

/** Frozen submitted-client envelope. It deliberately has no FiPA profile/step marker. */
export const legacyChallengeSchema = z.strictObject({
  client_id: text,
  scope: z.string().min(1).max(2048),
  response_type: z.literal("code").optional(),
  code_challenge: digest,
  code_challenge_method: z.literal("S256"),
  auth_session: z.string().min(1).max(128).optional(),
  intent: z
    .enum(["authenticate", "login", "create_account", "step_up"])
    .optional(),
  login_hint: z.string().max(320).optional(),
  email: z.string().max(320).optional(),
  password: z.string().min(1).max(1024).optional(),
  verification_code: z.string().min(1).max(256).optional(),
  new_password: z.string().min(1).max(1024).optional(),
  display_name: z.string().min(1).max(256).optional(),
  acr_values: z.string().max(1024).optional(),
  max_age: z.number().int().nonnegative().max(31536000).optional(),
  platform: z.literal("ios").optional(),
  device_attestation: z
    .strictObject({
      challenge_token: digest,
      key_id: z.string().min(1).max(1024),
      evidence: z.string().min(1).max(16384),
    })
    .optional(),
  dpop_jkt: digest,
  redirect_uri: z.string().min(1).max(2048),
  resource: z
    .union([
      z.string().min(1).max(2048),
      z.array(z.string().min(1).max(2048)).min(1).max(8),
    ])
    .optional(),
});
export type LegacyChallengeRequest = z.infer<typeof legacyChallengeSchema>;
export interface LegacyClientPolicy {
  clientId: string;
  provider: string;
  applicationId: string;
  environment: "development" | "production";
  redirectUris: readonly string[];
  scopes: readonly string[];
  resources: readonly string[];
  sessionLifetimeSeconds: number;
  /** Host-defined ACR labels satisfied by a fresh, completed password sign-in.
   * Never configure labels requiring MFA or password setup here. */
  passwordAcrValues?: readonly string[];
  /** Allow fresh password step-up from a completed, still-active library login.
   * Does not import old host handles or extend their evidence/session lifetime. */
  allowPasswordReauthentication?: boolean;
}

export function legacyPasswordAcr(
  request: Pick<LegacyChallengeRequest, "acr_values" | "intent">,
  policy: LegacyClientPolicy,
): string | null {
  const values = request.acr_values?.trim().split(/\s+/).filter(Boolean) ?? [];
  if (!values.length) return null;
  const selected = values.find((value) =>
    policy.passwordAcrValues?.includes(value),
  );
  if (!selected || request.intent === "create_account")
    throw invalidLegacyRequest();
  return selected;
}

/** Parser selection is explicit configuration, never a retry after failed proof verification. */
export function parseLegacyChallenge(
  parameters: Record<string, unknown>,
  policy: LegacyClientPolicy,
): { request: LegacyChallengeRequest; binding: OAuthAuthorizationBinding } {
  const parsed = legacyChallengeSchema.safeParse(parameters);
  if (!parsed.success) throw invalidLegacyRequest();
  const request = parsed.data;
  if (request.client_id !== policy.clientId) throw invalidLegacyRequest();
  // Only an explicit host policy can say which labels a fresh password proves.
  // Unknown requirements never become an ordinary password request.
  legacyPasswordAcr(request, policy);
  const binding = normalizeOAuthBinding({
    clientId: request.client_id,
    redirectUri: request.redirect_uri,
    codeChallenge: request.code_challenge,
    codeChallengeMethod: "S256",
    dpopJkt: request.dpop_jkt,
    scope: request.scope,
    ...(request.resource === undefined
      ? {}
      : {
          resources:
            typeof request.resource === "string"
              ? [request.resource]
              : request.resource,
        }),
  });
  if (
    !policy.redirectUris.includes(binding.redirectUri) ||
    binding.scope.split(" ").some((scope) => !policy.scopes.includes(scope)) ||
    (binding.resources ?? []).some(
      (resource) => !policy.resources.includes(resource),
    )
  )
    throw invalidLegacyRequest();
  // New continuation capabilities can never be presented as legacy ones. A
  // legacy-looking handle still requires an authenticated server-side lookup.
  if (
    request.auth_session &&
    !/^(?:fpls1_)?[A-Za-z0-9_-]{43}$/.test(request.auth_session)
  )
    throw invalidLegacyRequest();
  return { request, binding };
}
export function invalidLegacyRequest(): APIError {
  return new APIError("BAD_REQUEST", { error: "invalid_request" });
}
