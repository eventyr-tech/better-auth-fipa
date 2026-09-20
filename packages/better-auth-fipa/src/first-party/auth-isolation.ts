import type { GenericEndpointContext } from "@better-auth/core";

type Context = GenericEndpointContext["context"];
type Adapter = Context["internalAdapter"];
export function isolatedAuthHeaders(headers: Headers | undefined) {
  const isolated = new Headers(headers);
  for (const name of ["cookie", "authorization", "dpop"]) isolated.delete(name);
  isolated.set("content-type", "application/json");
  return isolated;
}
/** Clear ambient identity, while preserving the host's endpoint hook pipeline. */
export function isolatedAuthContext(
  context: Context,
  internalAdapter: Adapter = context.internalAdapter,
): Context {
  return { ...context, session: null, newSession: null, internalAdapter };
}
/** Observe every successful creation, including sessions created by host hooks.
 * Callers that need pre-write tracking retain their specialized creator. */
export function captureSessionCreation(
  adapter: Adapter,
  created: (token: string, userId: string) => void,
): Adapter {
  return {
    ...adapter,
    createSession: async (...args) => {
      const session = await adapter.createSession(...args);
      if (session) created(session.token, session.userId);
      return session;
    },
  };
}
