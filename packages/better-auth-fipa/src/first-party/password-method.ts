import type { GenericEndpointContext } from "@better-auth/core";
import { signInEmail } from "better-auth/api";
import {
  authenticateWithMethod,
  type AuthenticationMethodResult,
} from "./authentication-method.js";

export type PasswordMethodResult = AuthenticationMethodResult<"pwd">;

/** Invoke only after admission and one-use step reservation. */
export function authenticateWithPassword(
  ctx: GenericEndpointContext,
  input: { email: string; password: string },
): Promise<PasswordMethodResult> {
  return authenticateWithMethod(ctx, {
    endpoint: signInEmail(),
    body: { email: input.email, password: input.password, rememberMe: false },
    method: "pwd",
  });
}
