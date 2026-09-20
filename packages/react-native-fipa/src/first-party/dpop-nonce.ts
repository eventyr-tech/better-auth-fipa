import { FirstPartyClientError } from "./errors.ts";

type Response = {
  status: number;
  body: string;
  headers?: Record<string, string>;
};

function header(response: Response, name: string): string | undefined {
  const values = Object.entries(response.headers ?? {}).filter(
    ([key]) => key.toLowerCase() === name,
  );
  if (values.length > 1) throw new FirstPartyClientError("invalid_response");
  return values[0]?.[1];
}

function resourceChallenge(value: string | undefined): boolean {
  const match = value?.match(/^DPoP[ \t]+(.+)$/i);
  if (!match || value!.length > 8192 || /,[ \t]*$/.test(match[1]!))
    return false;
  // Accept one unambiguous DPoP challenge, with token or quoted parameters.
  const parameter =
    /([!#$%&'*+.^_`|~0-9a-z-]+)[ \t]*=[ \t]*(?:"((?:[\x20-\x21\x23-\x5B\x5D-\x7E]|\\[\x20-\x7E])*)"|([!#$%&'*+.^_`|~0-9a-z-]+))[ \t]*(?:,[ \t]*|$)/giy;
  const fields = new Map<string, string>();
  let offset = 0;
  while (offset < match[1]!.length) {
    const part = parameter.exec(match[1]!);
    if (!part || fields.has(part[1]!.toLowerCase())) return false;
    fields.set(
      part[1]!.toLowerCase(),
      part[2]?.replace(/\\(.)/g, "$1") ?? part[3]!,
    );
    offset = parameter.lastIndex;
  }
  return fields.get("error") === "use_dpop_nonce";
}

/** RFC 9449 sections 8–9: an explicit rejection, not a nonce header alone,
 * authorizes retry. The caller retains this nonce only for the same request. */
export function rejectedDpopNonce(
  response: Response,
  resource: boolean,
): string | undefined {
  let challenged = false;
  if (resource && response.status === 401)
    challenged = resourceChallenge(header(response, "www-authenticate"));
  else if (!resource && response.status === 400) {
    try {
      const body: unknown = JSON.parse(response.body);
      challenged =
        body !== null &&
        typeof body === "object" &&
        "error" in body &&
        body.error === "use_dpop_nonce";
    } catch {
      /* Ordinary malformed response handling belongs to the caller. */
    }
  }
  if (!challenged) return undefined;
  const nonce = header(response, "dpop-nonce");
  if (
    !nonce ||
    nonce.length > 1024 ||
    !/^[\x21\x23-\x5B\x5D-\x7E]+$/.test(nonce)
  )
    throw new FirstPartyClientError("invalid_response");
  return nonce;
}
