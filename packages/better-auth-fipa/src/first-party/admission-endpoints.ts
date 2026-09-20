import { isAndroidHardwareProvider } from "../android/provider.js";
import {
  createAndroidKeyChallenge,
  registerAndroidKey,
  createAndroidAdmissionChallenge,
  verifyAndroidAdmission,
  androidRegistrationSchema,
} from "./android-admission.js";
import { APIError, createAuthEndpoint, isAPIError } from "better-auth/api";
import { z } from "zod";
import { DeviceAttestationError } from "../errors.js";
import {
  createNativeAdmissionChallenge,
  verifyNativeAdmission,
  type NativeApplicationPolicy,
} from "./admission.js";
import { nativeAdmissionBindingSchema } from "./admission-binding.js";
import { readBoundedJson } from "./wire.js";

const challenge = z.strictObject({
  binding: nativeAdmissionBindingSchema,
  keyId: z.string().min(1).max(2048),
});
const verification = z.strictObject({
  clientId: z.string().min(1).max(256),
  challengeToken: z.string().min(1).max(128),
  keyId: z.string().min(1).max(2048),
  evidence: z.string().min(1),
});

/** New-purpose admission is distinct from the existing registration/grant routes. */
export function createNativeAdmissionEndpoints(
  applications: readonly NativeApplicationPolicy[],
) {
  const clients = new Map(applications.map((app) => [app.clientId, app]));
  if (!clients.size || clients.size !== applications.length)
    throw new TypeError(
      "Native application client IDs must be nonempty and unique.",
    );
  const maxEvidenceBytes = Math.max(
    ...applications.map((app) => app.provider.maxEvidenceBytes),
  );
  if (
    !Number.isSafeInteger(maxEvidenceBytes) ||
    maxEvidenceBytes < 1 ||
    maxEvidenceBytes > 1024 * 1024
  )
    throw new TypeError(
      "Native provider evidence must be bounded to at most one MiB.",
    );
  const endpoint = (operation: "challenge" | "verify") =>
    createAuthEndpoint(
      `/first-party/attestation/${operation}` as const,
      { method: "POST", disableBody: true, requireRequest: true },
      async (ctx) => {
        ctx.setHeader("Cache-Control", "no-store");
        ctx.setHeader("Pragma", "no-cache");
        try {
          const raw = await readBoundedJson(
            ctx.request,
            operation === "challenge"
              ? 32 * 1024
              : Math.ceil(maxEvidenceBytes / 3) * 4 + 4096,
          );
          if (operation === "challenge") {
            const input = challenge.safeParse(raw);
            if (!input.success) throw invalidRequest();
            const application = clients.get(input.data.binding.clientId);
            if (!application) throw invalidRequest();
            return ctx.json(
              await (isAndroidHardwareProvider(application.provider)
                ? createAndroidAdmissionChallenge(
                    ctx,
                    application,
                    input.data,
                    ctx.request.headers,
                  )
                : createNativeAdmissionChallenge(ctx, application, input.data)),
            );
          }
          const input = verification.safeParse(raw);
          if (!input.success) throw invalidRequest();
          const application = clients.get(input.data.clientId);
          if (!application) throw invalidRequest();
          return ctx.json(
            await (isAndroidHardwareProvider(application.provider)
              ? verifyAndroidAdmission(
                  ctx,
                  application,
                  input.data,
                  ctx.request.headers,
                )
              : verifyNativeAdmission(ctx, application, input.data)),
          );
        } catch (error) {
          if (isAPIError(error)) throw error;
          if (error instanceof DeviceAttestationError)
            throw new APIError("BAD_REQUEST", {
              error: "invalid_request",
              code: error.code,
            });
          // Provider and stored-state errors never escape into native UI or logs.
          throw invalidRequest();
        }
      },
    );
  const androidEndpoint = (operation: "key-challenge" | "register") =>
    createAuthEndpoint(
      `/first-party/android/${operation}` as const,
      { method: "POST", disableBody: true, requireRequest: true },
      async (ctx) => {
        ctx.setHeader("Cache-Control", "no-store");
        ctx.setHeader("Pragma", "no-cache");
        try {
          const raw = await readBoundedJson(
            ctx.request,
            operation === "key-challenge" ? 4096 : 180_000,
          );
          if (operation === "key-challenge") {
            const input = z
              .strictObject({ clientId: z.string().min(1).max(256) })
              .safeParse(raw);
            if (!input.success) throw invalidRequest();
            const application = clients.get(input.data.clientId);
            if (
              !application ||
              !isAndroidHardwareProvider(application.provider)
            )
              throw invalidRequest();
            return ctx.json(await createAndroidKeyChallenge(ctx, application));
          }
          const input = androidRegistrationSchema.safeParse(raw);
          if (!input.success) throw invalidRequest();
          const application = clients.get(input.data.binding.clientId);
          if (!application || !isAndroidHardwareProvider(application.provider))
            throw invalidRequest();
          return ctx.json(
            await registerAndroidKey(
              ctx,
              application,
              input.data,
              ctx.request.headers,
            ),
          );
        } catch (error) {
          if (isAPIError(error)) throw error;
          if (error instanceof DeviceAttestationError)
            throw new APIError("BAD_REQUEST", {
              error: "invalid_request",
              code: error.code,
            });
          throw invalidRequest();
        }
      },
    );
  return {
    firstPartyAndroidKeyChallenge: androidEndpoint("key-challenge"),
    firstPartyAndroidRegister: androidEndpoint("register"),
    firstPartyAttestationChallenge: endpoint("challenge"),
    firstPartyAttestationVerify: endpoint("verify"),
  };
}

function invalidRequest() {
  return new APIError("BAD_REQUEST", { error: "invalid_request" });
}
