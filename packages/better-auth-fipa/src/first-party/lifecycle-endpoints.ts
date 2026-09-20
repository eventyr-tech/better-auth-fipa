import { APIError, createAuthEndpoint, isAPIError } from "better-auth/api";
import { z } from "zod";
import { readBoundedJson } from "./wire.js";
import {
  terminateNativeSession,
  type NativeTokenOptions,
} from "./token-lifecycle.js";

/** No caller-supplied target IDs: each action is scoped to the proven token. */
export function createNativeLifecycleEndpoints(options: NativeTokenOptions) {
  const endpoint = (action: "logout" | "retire") => {
    const path = `/first-party/${action}` as const;
    return createAuthEndpoint(
      path,
      { method: "POST", disableBody: true, requireRequest: true },
      async (ctx) => {
        ctx.setHeader("Cache-Control", "no-store");
        ctx.setHeader("Pragma", "no-cache");
        try {
          const body = (
            action === "logout"
              ? z.strictObject({ scope: z.literal("family").optional() })
              : z.strictObject({})
          ).safeParse(await readBoundedJson(ctx.request, 256));
          if (!body.success)
            throw new APIError("BAD_REQUEST", { error: "invalid_request" });
          await terminateNativeSession(ctx, options, {
            headers: ctx.request.headers,
            // Use the configured issuer, never an incoming Host/Forwarded value.
            url: `${ctx.context.baseURL}${path}`,
            action,
            ...(action === "logout" &&
            "scope" in body.data &&
            body.data.scope === "family"
              ? { familyOnly: true }
              : {}),
          });
        } catch (error) {
          if (isAPIError(error)) throw error;
          throw new APIError("INTERNAL_SERVER_ERROR", {
            error: "server_error",
          });
        }
        return ctx.json({ success: true });
      },
    );
  };
  return {
    firstPartyLogout: endpoint("logout"),
    firstPartyRetire: endpoint("retire"),
  };
}
