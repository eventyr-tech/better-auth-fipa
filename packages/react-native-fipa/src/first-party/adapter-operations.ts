import { isLocalHostname } from "./local-origin.ts";
import { z } from "zod";
import type {
  FirstPartyClientPorts,
  NativeIdentity,
  NativeBinding,
  ResourceResponse,
} from "./client.ts";
import { FirstPartyClientError } from "./errors.ts";
import { identifier } from "./identity.ts";

export const aliasesSchema = z.strictObject({
  dpopAlias: identifier,
  providerScope: identifier,
});
const proofSchema = z
  .string()
  .max(16384)
  .regex(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
export function checkCancelled(signal?: AbortSignal) {
  if (signal?.aborted) throw new FirstPartyClientError("cancelled");
}
export function parseResponse<T>(schema: z.ZodType<T>, value: unknown): T {
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw new FirstPartyClientError("invalid_response");
  return parsed.data;
}
function code(error: unknown) {
  return error && typeof error === "object" && "code" in error
    ? error.code
    : undefined;
}
export function transportError(error: unknown): FirstPartyClientError {
  if (error instanceof FirstPartyClientError) return error;
  if (code(error) === "http_cancelled")
    return new FirstPartyClientError("cancelled");
  if (
    [
      "http_redirect_rejected",
      "http_invalid_response",
      "http_response_too_large",
    ].includes(String(code(error)))
  )
    return new FirstPartyClientError("invalid_response");
  return new FirstPartyClientError("request_failed");
}
/** No retry or original native exception escapes this boundary. Cancellation wins. */
export async function nativeOperation<T>(
  operation: () => Promise<T>,
  signal?: AbortSignal,
): Promise<T> {
  checkCancelled(signal);
  try {
    const value = await operation();
    checkCancelled(signal);
    return value;
  } catch (error) {
    checkCancelled(signal);
    if (error instanceof FirstPartyClientError) throw error;
    const permanent = code(error);
    if (
      permanent === "app_attest_unavailable" ||
      permanent === "key_unavailable" ||
      permanent === "key_locked" ||
      permanent === "key_invalid_input"
    )
      throw new FirstPartyClientError(permanent);
    if (code(error) === "key_missing")
      throw new FirstPartyClientError("registration_recovery_required");
    throw new FirstPartyClientError("operation_failed");
  }
}
export function normalizeIssuer(
  value: string,
  allowInsecureLoopback = false,
): string {
  try {
    const url = new URL(value);
    if (
      url.username ||
      url.password ||
      url.search ||
      url.hash ||
      (url.protocol !== "https:" &&
        !(
          allowInsecureLoopback &&
          url.protocol === "http:" &&
          isLocalHostname(url.hostname)
        ))
    )
      throw new Error();
    return url.href.replace(/\/+$/u, "");
  } catch {
    throw new FirstPartyClientError("invalid_configuration");
  }
}
export function validateResponse(
  response: Pick<ResourceResponse, "url" | "status" | "body">,
  url: string,
  limit: number,
) {
  if (
    response.url !== url ||
    !Number.isInteger(response.status) ||
    response.status < 200 ||
    response.status >= 600 ||
    (response.status >= 300 && response.status < 400) ||
    new TextEncoder().encode(response.body).byteLength > limit
  )
    throw new FirstPartyClientError("invalid_response");
}
export function jsonResponse(body: string): unknown {
  try {
    return JSON.parse(body) as unknown;
  } catch {
    throw new FirstPartyClientError("invalid_response");
  }
}
export function successfulResponse(response: {
  status: number;
  body: unknown;
}) {
  if (response.status !== 200)
    throw new FirstPartyClientError("request_failed");
  return response.body;
}
type Sign = (
  alias: string,
  jkt: string,
  url: string,
  method: string,
  token: string | null,
  nonce: string | null,
) => Promise<string>;
export async function signProof(
  sign: Sign,
  identity: NativeIdentity,
  request: Parameters<FirstPartyClientPorts["keys"]["proof"]>[1],
) {
  return parseResponse(
    proofSchema,
    await nativeOperation(() =>
      sign(
        identity.dpopAlias,
        identity.dpopJkt,
        request.url,
        request.method,
        request.accessToken ?? null,
        request.nonce ?? null,
      ),
    ),
  );
}
/** Signing is opt-in per request: pre-key challenges must remain unsigned. */
export function createAdmissionTransport(
  issuer: string,
  send: FirstPartyClientPorts["send"],
  proof?: FirstPartyClientPorts["keys"]["proof"],
) {
  return async (
    path: string,
    body: unknown,
    signal: AbortSignal,
    identity?: NativeIdentity,
  ) => {
    checkCancelled(signal);
    const url = `${issuer}${path}`;
    const headers: Record<string, string> = {
      Accept: "application/json",
      "Content-Type": "application/json",
    };
    if (identity) {
      if (!proof) throw new FirstPartyClientError("invalid_state");
      headers.DPoP = await nativeOperation(
        () => proof(identity, { url, method: "POST" }),
        signal,
      );
    }
    checkCancelled(signal);
    let response: Awaited<ReturnType<FirstPartyClientPorts["send"]>>;
    try {
      response = await send({
        url,
        method: "POST",
        headers,
        body: JSON.stringify(body),
        signal,
        maximumResponseBytes: 65536,
      });
    } catch (error) {
      checkCancelled(signal);
      throw transportError(error);
    }
    checkCancelled(signal);
    validateResponse(response, url, 65536);
    return { status: response.status, body: jsonResponse(response.body) };
  };
}

export function assertAdmissionBinding(
  binding: NativeBinding,
  identity: NativeIdentity,
  expected: Pick<
    NativeBinding,
    "issuer" | "clientId" | "applicationId" | "environment" | "provider"
  >,
) {
  if (
    binding.dpopJkt !== identity.dpopJkt ||
    Object.entries(expected).some(
      ([key, value]) => binding[key as keyof NativeBinding] !== value,
    )
  )
    throw new FirstPartyClientError("invalid_state");
}
