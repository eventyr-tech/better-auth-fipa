import { transportError } from "./adapter-operations.ts";
import { z } from "zod";
import type { Spec } from "../NativeFirstPartyTransport.ts";
import { FirstPartyClientError } from "./errors.ts";
import type { FirstPartyClientPorts } from "./client.ts";

type Native = Pick<Spec, "randomToken" | "transaction" | "send" | "cancel">;
const digest = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
const transaction = z.strictObject({
  id: digest,
  verifier: digest,
  challenge: digest,
});
const response = z.strictObject({
  url: z.url(),
  status: z.number().int().min(100).max(599),
  headersJSON: z.string().max(32768),
  body: z.string().max(1_048_576),
});

/** No JS fetch fallback: the native transport enforces redirect/cookie/TLS policy. */
export function createNativeProtocolTransport(
  native: Native,
  options: {
    allowInsecureLoopback?: boolean;
    timeoutMilliseconds?: number;
  } = {},
): Pick<FirstPartyClientPorts, "send" | "crypto"> {
  const timeout = options.timeoutMilliseconds ?? 30_000;
  if (!Number.isSafeInteger(timeout) || timeout < 1000 || timeout > 120_000)
    throw new FirstPartyClientError("invalid_configuration");
  return {
    crypto: {
      transaction: async () => {
        try {
          return transaction.parse(await native.transaction());
        } catch {
          throw new FirstPartyClientError("operation_failed");
        }
      },
    },
    send: async (request) => {
      if (request.signal.aborted) throw new FirstPartyClientError("cancelled");
      let requestId: string;
      try {
        requestId = digest.parse(await native.randomToken());
      } catch {
        throw new FirstPartyClientError("request_failed");
      }
      if (request.signal.aborted) throw new FirstPartyClientError("cancelled");
      let interrupted!: () => void;
      const cancelled = new Promise<never>((_, reject) => {
        interrupted = () => {
          // Cancellation is also enforced locally if the bridge stops responding.
          void native.cancel(requestId).catch(() => undefined);
          reject(new FirstPartyClientError("cancelled"));
        };
      });
      request.signal.addEventListener("abort", interrupted, { once: true });
      try {
        const result = await Promise.race([
          cancelled,
          native.send(
            requestId,
            request.url,
            request.method,
            JSON.stringify(request.headers),
            request.body,
            request.maximumResponseBytes,
            timeout,
            options.allowInsecureLoopback === true,
          ),
        ]);
        if (request.signal.aborted)
          throw new FirstPartyClientError("cancelled");
        const parsed = response.safeParse(result);
        if (!parsed.success)
          throw new FirstPartyClientError("invalid_response");
        let headers: Record<string, string>;
        try {
          const raw: unknown = JSON.parse(parsed.data.headersJSON);
          headers = z.record(z.string(), z.string()).parse(raw);
        } catch {
          throw new FirstPartyClientError("invalid_response");
        }
        return {
          url: parsed.data.url,
          status: parsed.data.status,
          body: parsed.data.body,
          headers,
        };
      } catch (error) {
        throw transportError(error);
      } finally {
        request.signal.removeEventListener("abort", interrupted);
      }
    },
  };
}
