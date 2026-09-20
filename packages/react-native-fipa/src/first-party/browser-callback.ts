import { FirstPartyClientError } from "./errors.ts";

const reserved = ["code", "state", "iss", "error"];
export function registeredCallback(value: string): string {
  try {
    const url = new URL(value);
    if (
      value.length > 2048 ||
      url.username ||
      url.password ||
      url.hash ||
      !/^(https:|[a-z][a-z0-9+.-]*:)$/.test(url.protocol) ||
      ["http:", "javascript:", "data:", "file:", "about:"].includes(
        url.protocol,
      ) ||
      reserved.some((name) => url.searchParams.has(name))
    )
      throw new Error();
    // Registration is exact, including query parameters and trailing slashes.
    return value;
  } catch {
    throw new FirstPartyClientError("invalid_configuration");
  }
}

/** Browser URLs/codes never leave the SDK as consumer state or error details. */
export function authorizationCallback(
  value: string,
  expected: { redirectUri: string; state: string; issuer: string },
): string {
  try {
    if (value.length > 32768) throw new Error();
    const callback = new URL(value);
    const registered = new URL(expected.redirectUri);
    const parameters = callback.searchParams;
    if (
      callback.hash ||
      callback.username ||
      callback.password ||
      parameters.getAll("state").length !== 1 ||
      parameters.get("state") !== expected.state ||
      parameters.getAll("iss").length !== 1 ||
      parameters.get("iss") !== expected.issuer ||
      parameters.getAll("code").length + parameters.getAll("error").length !== 1
    )
      throw new Error();
    const code = parameters.get("code");
    const denied = parameters.has("error");
    for (const name of reserved) parameters.delete(name);
    if (
      callback.href !== registered.href ||
      (!denied && (!code || code.length > 16384))
    )
      throw new Error();
    if (denied) throw new FirstPartyClientError("browser_failed");
    return code!;
  } catch (error) {
    if (error instanceof FirstPartyClientError) throw error;
    throw new FirstPartyClientError("invalid_response");
  }
}
