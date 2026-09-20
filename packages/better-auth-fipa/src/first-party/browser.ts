import { requireUserSecurity, userSecurityHash } from "./user-security.js";
import type { BetterAuthOptions } from "better-auth";
import type { GenericEndpointContext } from "@better-auth/core";
import { getFirstPartyOAuthApi } from "./oauth-api.js";
import {
  APIError,
  createAuthEndpoint,
  createAuthMiddleware,
  dispatchAuthEndpoint,
  getSession,
  isAPIError,
} from "better-auth/api";
import { z } from "zod";
import { hmacSha256 } from "../protocol/crypto.js";
import { requireNativeApplicationPolicy } from "./admission.js";
import {
  activeAttempt,
  checkProvider,
  completeAttempt,
  lockCredential,
  lookupSession,
  newHandle,
  proveSession,
  randomId,
  rotateSession,
  updateAttempt,
  type ContinuationInput,
  type NativeInteraction,
  type NativeSession,
} from "./continuation.js";
import type { NativeTokenOptions } from "./token-lifecycle.js";
import { withFirstPartyTransaction } from "./transaction.js";

const PREFIX = "urn:ietf:params:oauth:request_uri:fpb1_";
const COMPLETE = "/first-party/browser/complete";
interface BrowserHandoff {
  id: string;
  requestHash: string;
  cookieHash: string | null;
  clientId: string;
  sessionId: string;
  attemptId: string;
  stepId: string;
  redirectUri: string;
  state: string;
  status: "prepared" | "opened" | "consumed";
  openedAt: Date | null;
  expiresAt: Date;
}

interface BrowserAuthentication {
  userId: string;
  createdAt: Date;
  expiresAt: Date;
  firstPartyBrowserHandoffId?: string | null;
  firstPartyBrowserSecurityHash?: string | null;
}

/** Stamp the BA session at creation, never at refresh or native completion.
 * OAuth Provider requires database-backed sessions even with secondary storage.
 * These private fields are read from that authoritative row, not a cookie cache.
 */
export const nativeBrowserSessionHooks = {
  session: {
    create: {
      before: async (data, ctx) => {
        if (!ctx?.headers?.get("cookie")) return;
        const nonce = await ctx.getSignedCookie(
          browserCookie(ctx).name,
          ctx.context.secret,
        );
        if (!nonce || !/^[A-Za-z0-9_-]{43}$/.test(nonce)) return;
        return withFirstPartyTransaction(ctx, async (tx) => {
          const handoff = await tx.context.adapter.findOne<BrowserHandoff>({
            model: "firstPartyBrowser",
            where: [
              { field: "cookieHash", value: digest(tx, "cookie", nonce) },
            ],
          });
          if (
            !handoff ||
            handoff.status !== "opened" ||
            !handoff.openedAt ||
            handoff.expiresAt <= new Date()
          )
            return;
          return {
            data: {
              ...data,
              firstPartyBrowserHandoffId: handoff.id,
              firstPartyBrowserSecurityHash: await userSecurityHash(
                tx,
                data.userId,
              ),
            },
          };
        });
      },
    },
  },
} satisfies NonNullable<BetterAuthOptions["databaseHooks"]>;

/** Only a proven native continuation may carry accepted evidence into the browser. */
export async function prepareNativeBrowser(
  ctx: GenericEndpointContext,
  options: NativeTokenOptions,
  input: ContinuationInput & {
    stepId: string;
    redirectUri: string;
    state: string;
  },
): Promise<NativeInteraction> {
  loginPage(ctx, options);
  const session = await proveSession(ctx, input);
  await requireCallback(ctx, options, input.clientId, input.redirectUri);
  if (!/^[A-Za-z0-9_-]{32,128}$/.test(input.state)) throw invalidRequest();
  return withFirstPartyTransaction(ctx, async (tx) => {
    await lockCredential(
      tx,
      session.credentialId,
      session.credentialVersion,
      session.clientId,
      session.dpopJkt,
    );
    const current = await lookupSession(tx, input.authSession, input.clientId);
    const attempt = await activeAttempt(tx, current, input.stepId);
    if (attempt.status !== "browser" || attempt.evidenceExpiresAt <= new Date())
      throw invalidRequest();
    await checkProvider(tx, current, attempt);
    const requestUri = `${PREFIX}${randomId()}`;
    const stepId = randomId();
    const expiresAt = new Date(
      Math.min(
        Date.now() + 300_000,
        attempt.expiresAt.getTime(),
        attempt.evidenceExpiresAt.getTime(),
        current.expiresAt.getTime(),
        current.absoluteExpiresAt.getTime(),
      ),
    );
    await tx.context.adapter.create<BrowserHandoff>({
      model: "firstPartyBrowser",
      data: {
        requestHash: digest(tx, "request", requestUri),
        cookieHash: null,
        clientId: current.clientId,
        sessionId: current.id,
        attemptId: attempt.id,
        stepId,
        redirectUri: input.redirectUri,
        state: input.state,
        status: "prepared",
        openedAt: null,
        expiresAt,
      },
    });
    await updateAttempt(tx, attempt, { stepId });
    const handle = newHandle();
    await rotateSession(tx, current, handle, options.lifetimes);
    return {
      kind: "browser",
      authSession: handle,
      requestUri,
      expiresIn: Math.max(
        0,
        Math.floor((expiresAt.getTime() - Date.now()) / 1000),
      ),
      stepId,
    };
  });
}

/** Public OAuth authorization route, with stored native provenance taking priority. */
export function createNativeBrowserHook(options: NativeTokenOptions) {
  const clients = new Set(
    options.applications.map((application) => application.clientId),
  );
  return {
    matcher: (ctx: { path?: string; query?: Record<string, unknown> }) =>
      ctx.path === "/oauth2/authorize" &&
      ((typeof ctx.query?.client_id === "string" &&
        clients.has(ctx.query.client_id)) ||
        (typeof ctx.query?.request_uri === "string" &&
          ctx.query.request_uri.startsWith(PREFIX))),
    handler: createAuthMiddleware(async (ctx) => {
      securityHeaders(ctx);
      const page = loginPage(ctx, options);
      if (!ctx.request || ctx.request.method !== "GET") throw invalidRequest();
      const query = new URL(ctx.request.url).searchParams;
      if (
        [...query.keys()].some(
          (key) => key !== "client_id" && key !== "request_uri",
        ) ||
        query.getAll("client_id").length !== 1 ||
        query.getAll("request_uri").length !== 1
      )
        throw invalidRequest();
      const requestUri = query.get("request_uri")!;
      if (
        !requestUri.startsWith(PREFIX) ||
        !/^[A-Za-z0-9_-]{43}$/.test(requestUri.slice(PREFIX.length))
      )
        throw invalidRequest();
      const handoff = await ctx.context.adapter.findOne<BrowserHandoff>({
        model: "firstPartyBrowser",
        where: [
          { field: "requestHash", value: digest(ctx, "request", requestUri) },
        ],
      });
      if (
        !handoff ||
        handoff.clientId !== query.get("client_id") ||
        handoff.status !== "prepared"
      )
        throw invalidRequest();
      await requireCallback(
        ctx,
        options,
        handoff.clientId,
        handoff.redirectUri,
      );
      const nonce = randomId();
      await withFirstPartyTransaction(ctx, async (tx) => {
        await lockedAttempt(tx, options, handoff);
        const claimed = await tx.context.adapter.incrementOne<BrowserHandoff>({
          model: "firstPartyBrowser",
          where: [
            { field: "id", value: handoff.id },
            { field: "status", value: "prepared" },
            { field: "expiresAt", operator: "gt", value: new Date() },
          ],
          increment: {},
          set: {
            status: "opened",
            openedAt: new Date(),
            cookieHash: digest(tx, "cookie", nonce),
          },
        });
        if (!claimed) throw invalidRequest();
      });
      const cookie = browserCookie(ctx);
      await ctx.setSignedCookie(
        cookie.name,
        nonce,
        ctx.context.secret,
        cookie.attributes,
      );
      page.searchParams.set("callbackURL", `${ctx.context.baseURL}${COMPLETE}`);
      page.searchParams.set("prompt", "login");
      throw ctx.redirect(page.href);
    }),
  };
}

export function createNativeBrowserCompleteEndpoint(
  options: NativeTokenOptions,
) {
  return createAuthEndpoint(
    COMPLETE,
    { method: "GET", requireHeaders: true, requireRequest: true },
    async (ctx) => {
      securityHeaders(ctx);
      loginPage(ctx, options);
      const cookie = browserCookie(ctx);
      const nonce = await ctx.getSignedCookie(cookie.name, ctx.context.secret);
      if (
        !nonce ||
        !/^[A-Za-z0-9_-]{43}$/.test(nonce) ||
        new URL(ctx.request.url).search
      )
        throw invalidRequest();
      const handoff = await ctx.context.adapter.findOne<BrowserHandoff>({
        model: "firstPartyBrowser",
        where: [{ field: "cookieHash", value: digest(ctx, "cookie", nonce) }],
      });
      if (
        !handoff ||
        handoff.status !== "opened" ||
        !handoff.openedAt ||
        handoff.expiresAt <= new Date()
      )
        throw invalidRequest();
      await requireCallback(
        ctx,
        options,
        handoff.clientId,
        handoff.redirectUri,
      );
      // Read through the full Better Auth hook pipeline with no bearer fallback and
      // no cookie cache. Never infer authentication from a browser request body.
      const headers = new Headers(ctx.headers);
      headers.delete("authorization");
      headers.delete("dpop");
      const result = await dispatchAuthEndpoint(getSession(), {
        context: { ...ctx.context, session: null, newSession: null },
        headers,
        method: "GET",
        query: { disableCookieCache: true, disableRefresh: true },
        request: new Request(
          `${ctx.context.baseURL}/get-session?disableCookieCache=true&disableRefresh=true`,
          { headers },
        ),
        asResponse: true,
      });
      if (!(result instanceof Response) || !result.ok) throw unauthorized();
      const authenticated = z
        .object({
          user: z.object({ id: z.string() }),
          session: z.object({ token: z.string() }),
        })
        .safeParse(await result.json());
      if (!authenticated.success) throw unauthorized();
      const outcome = await withFirstPartyTransaction(ctx, async (tx) => {
        const { session, attempt, logical, provider } = await lockedAttempt(
          tx,
          options,
          handoff,
        );
        const live = await tx.context.internalAdapter.findSession(
          authenticated.data.session.token,
        );
        if (
          !live ||
          live.user.id !== authenticated.data.user.id ||
          live.session.createdAt <= handoff.openedAt! ||
          live.session.expiresAt <= new Date() ||
          (ctx.context.options.emailAndPassword?.requireEmailVerification &&
            !live.user.emailVerified) ||
          (logical.userId && logical.userId !== live.user.id) ||
          (provider.userId && provider.userId !== live.user.id)
        )
          throw unauthorized();
        const authentication =
          await tx.context.adapter.findOne<BrowserAuthentication>({
            model: "session",
            where: [
              {
                field: "token",
                value: authenticated.data.session.token,
              },
            ],
          });
        if (
          !authentication ||
          authentication.firstPartyBrowserHandoffId !== handoff.id ||
          typeof authentication.firstPartyBrowserSecurityHash !== "string" ||
          authentication.userId !== live.user.id ||
          authentication.createdAt.getTime() !==
            live.session.createdAt.getTime() ||
          authentication.expiresAt <= new Date()
        )
          throw unauthorized();
        try {
          await requireUserSecurity(
            tx,
            live.user.id,
            authentication.firstPartyBrowserSecurityHash,
          );
        } catch (error) {
          if (isAPIError(error) && error.statusCode === 400)
            throw unauthorized();
          throw error;
        }
        const claimed = await tx.context.adapter.incrementOne<BrowserHandoff>({
          model: "firstPartyBrowser",
          where: [
            { field: "id", value: handoff.id },
            { field: "status", value: "opened" },
            { field: "cookieHash", value: handoff.cookieHash },
            { field: "expiresAt", operator: "gt", value: new Date() },
          ],
          increment: {},
          set: { status: "consumed" },
        });
        if (!claimed) throw invalidRequest();
        const next = await updateAttempt(tx, attempt, {
          status: "processing",
          userId: live.user.id,
          userSecurityHash: authentication.firstPartyBrowserSecurityHash,
          authenticatedAt: live.session.createdAt,
          authenticationMethods: ["urn:better-auth:browser-session"],
        });
        const handle = newHandle();
        const rotated = await rotateSession(
          tx,
          session,
          handle,
          options.lifetimes,
        );
        return completeAttempt(
          tx,
          options.lifetimes,
          rotated,
          next,
          handle,
          handoff.redirectUri,
        );
      });
      if (outcome.kind !== "authorized") throw invalidRequest();
      const callback = new URL(handoff.redirectUri);
      callback.searchParams.set("code", outcome.authorizationCode);
      callback.searchParams.set("state", handoff.state);
      callback.searchParams.set("iss", ctx.context.baseURL);
      ctx.setCookie(cookie.name, "", { ...cookie.attributes, maxAge: 0 });
      throw ctx.redirect(callback.href);
    },
  );
}

async function lockedAttempt(
  ctx: GenericEndpointContext,
  options: NativeTokenOptions,
  handoff: BrowserHandoff,
) {
  const session = await ctx.context.adapter.findOne<NativeSession>({
    model: "firstPartySession",
    where: [{ field: "id", value: handoff.sessionId }],
  });
  if (!session) throw invalidRequest();
  const logical = await lockCredential(
    ctx,
    session.credentialId,
    session.credentialVersion,
    session.clientId,
    session.dpopJkt,
  );
  if (
    session.status !== "active" ||
    session.expiresAt <= new Date() ||
    session.absoluteExpiresAt <= new Date() ||
    handoff.expiresAt <= new Date() ||
    session.clientId !== handoff.clientId
  )
    throw invalidRequest();
  const attempt = await activeAttempt(ctx, session, handoff.stepId);
  if (
    attempt.id !== handoff.attemptId ||
    attempt.status !== "browser" ||
    attempt.evidenceExpiresAt <= new Date()
  )
    throw invalidRequest();
  const application = options.applications.find(
    (candidate) => candidate.clientId === session.clientId,
  );
  if (!application) throw invalidRequest();
  requireNativeApplicationPolicy(ctx, application, attempt.binding);
  const provider = await checkProvider(ctx, session, attempt);
  return { session, attempt, logical, provider };
}
async function requireCallback(
  ctx: GenericEndpointContext,
  options: NativeTokenOptions,
  clientId: string,
  redirectUri: string,
) {
  const client = await getFirstPartyOAuthApi(ctx, options.oauth).getClient(
    clientId,
  );
  let uri: URL;
  try {
    uri = new URL(redirectUri);
  } catch {
    throw invalidRequest();
  }
  if (
    !client ||
    client.disabled ||
    (client.expiresAt && client.expiresAt <= new Date()) ||
    client.tokenEndpointAuthMethod !== "none" ||
    !client.grantTypes?.includes("authorization_code") ||
    !client.redirectUris?.includes(redirectUri) ||
    uri.hash ||
    uri.username ||
    uri.password ||
    uri.protocol === "http:" ||
    !/^(https:|[a-z][a-z0-9+.-]*:)$/.test(uri.protocol) ||
    ["javascript:", "data:", "file:", "about:"].includes(uri.protocol) ||
    ["code", "state", "iss", "error"].some((key) => uri.searchParams.has(key))
  )
    throw invalidRequest();
}
function loginPage(ctx: GenericEndpointContext, options: NativeTokenOptions) {
  if (!options.browser) throw invalidRequest();
  const page = new URL(options.browser.loginPage, `${ctx.context.baseURL}/`);
  if (
    page.origin !== new URL(ctx.context.baseURL).origin ||
    page.username ||
    page.password ||
    page.hash
  )
    throw invalidRequest();
  return page;
}
function browserCookie(ctx: GenericEndpointContext) {
  return ctx.context.createAuthCookie("first_party_browser", {
    httpOnly: true,
    sameSite: "lax",
    maxAge: 300,
    path: new URL(ctx.context.baseURL).pathname || "/",
  });
}
function securityHeaders(ctx: GenericEndpointContext) {
  ctx.setHeader("Cache-Control", "no-store");
  ctx.setHeader("Pragma", "no-cache");
  ctx.setHeader("Referrer-Policy", "no-referrer");
}
function digest(
  ctx: GenericEndpointContext,
  kind: "request" | "cookie",
  value: string,
) {
  return hmacSha256(
    ctx.context.secret,
    `first-party-browser:${kind}:v1:${value}`,
  );
}
function invalidRequest() {
  return new APIError("BAD_REQUEST", { error: "invalid_request" });
}
function unauthorized() {
  return new APIError("UNAUTHORIZED", { error: "login_required" });
}
