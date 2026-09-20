import { APIError } from "better-auth/api";

/** Versioned extension identifier; independent of the FiPA draft revision. */
export const FIRST_PARTY_PROFILE = "device-attestation-fipa-v1";
const MAX_BODY_BYTES = 16 * 1024;
const MAX_RESOURCES = 8;
const SINGLETONS = new Set([
  "profile",
  "client_id",
  "response_type",
  "scope",
  "auth_session",
  "code_challenge",
  "code_challenge_method",
  "device_attestation",
  "dpop_jkt",
  "authorization_attempt",
  "nonce",
  "acr_values",
  "max_age",
  "login_hint",
  "step_id",
  "response",
]);

export type FirstPartyWireRequest =
  | { protocol: "legacy-v1"; parameters: Record<string, unknown> }
  | { protocol: "fipa-v1"; parameters: Record<string, string | string[]> };

/**
 * Dispatches by an explicit wire contract, never by failed security checks.
 * This selects a parser only: callers must still enforce registered-client
 * policy and server-owned continuation provenance before executing either flow.
 */
export async function parseFirstPartyWireRequest(
  request: Request,
  options: { legacyEnabled: boolean },
): Promise<FirstPartyWireRequest> {
  if (request.method !== "POST") {
    throw new APIError("METHOD_NOT_ALLOWED", { error: "invalid_request" });
  }
  const [mediaType, ...parameters] = (request.headers.get("content-type") ?? "")
    .toLowerCase()
    .split(";")
    .map((part) => part.trim());
  if (
    parameters.some(
      (parameter) => !/^charset=(?:utf-8|"utf-8")$/.test(parameter),
    )
  ) {
    throw new APIError("UNSUPPORTED_MEDIA_TYPE", { error: "invalid_request" });
  }
  if (
    mediaType !== "application/json" &&
    mediaType !== "application/x-www-form-urlencoded"
  ) {
    throw new APIError("UNSUPPORTED_MEDIA_TYPE", { error: "invalid_request" });
  }
  if (mediaType === "application/json" && !options.legacyEnabled) {
    throw new APIError("UNSUPPORTED_MEDIA_TYPE", { error: "invalid_request" });
  }
  const body = await readBoundedText(request, MAX_BODY_BYTES);
  if (mediaType === "application/json") {
    let decoded: unknown;
    try {
      decoded = JSON.parse(body);
    } catch {
      throw invalidRequest();
    }
    if (
      decoded === null ||
      typeof decoded !== "object" ||
      Array.isArray(decoded)
    ) {
      throw invalidRequest();
    }
    const legacy = decoded as Record<string, unknown>;
    // New-profile markers must not be accepted through the legacy parser.
    if ("profile" in legacy) throw invalidRequest();
    return { protocol: "legacy-v1", parameters: legacy };
  }
  // URLSearchParams replaces malformed encodings. Reject them before decoding
  // to avoid different canonical request bytes across runtimes.
  try {
    decodeURIComponent(body.replace(/\+/g, " "));
  } catch {
    throw invalidRequest();
  }
  const form = new URLSearchParams(body);
  const parsed: Record<string, string | string[]> = Object.create(
    null,
  ) as Record<string, string | string[]>;
  for (const [key, value] of form) {
    if (key === "resource") {
      const resources = parsed.resource as string[] | undefined;
      if (
        !value ||
        resources?.includes(value) ||
        (resources?.length ?? 0) >= MAX_RESOURCES
      )
        throw invalidRequest();
      if (resources) resources.push(value);
      else parsed.resource = [value];
    } else {
      if (!SINGLETONS.has(key) || Object.hasOwn(parsed, key))
        throw invalidRequest();
      parsed[key] = value;
    }
  }
  if (parsed.profile !== FIRST_PARTY_PROFILE) throw invalidRequest();
  return { protocol: "fipa-v1", parameters: parsed };
}

function invalidRequest(): APIError {
  return new APIError("BAD_REQUEST", { error: "invalid_request" });
}

export async function readBoundedText(
  request: Request,
  maxBytes: number,
): Promise<string> {
  const reader = request.body?.getReader();
  if (!reader) throw invalidRequest();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) {
        await reader.cancel();
        throw new APIError("PAYLOAD_TOO_LARGE", { error: "invalid_request" });
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw invalidRequest();
  }
}

export async function readBoundedJson(
  request: Request,
  limit: number,
): Promise<unknown> {
  if (
    !/^application\/json(?:\s*;\s*charset=(?:utf-8|"utf-8"))?\s*$/i.test(
      request.headers.get("content-type") ?? "",
    )
  )
    throw new APIError("UNSUPPORTED_MEDIA_TYPE", { error: "invalid_request" });
  const text = await readBoundedText(request, limit);
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw invalidRequest();
  }
}
