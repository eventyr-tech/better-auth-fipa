import {
  APIError,
  createAuthEndpoint,
  createAuthMiddleware,
} from "better-auth/api";
import { emailOTP, twoFactor } from "better-auth/plugins";
import type { BetterAuthPlugin } from "better-auth";
import { getTestInstance } from "./fixtures/auth-instance.js";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { authenticateWithPassword } from "./first-party/password-method.js";
import {
  authenticateWithEmailOTP,
  sendEmailOTP,
} from "./first-party/email-otp-method.js";

async function otpFixture(
  testWith: "sqlite" | "postgres",
  options: { disableSignUp?: boolean; installed?: boolean } = {},
) {
  const observed = {
    sent: [] as { email: string; otp: string; type: string }[],
    calls: [] as string[],
    ambient: [] as (string | null)[],
    limit: false,
    deny: false,
    failDelivery: false,
    revokeAfter: false,
    deliverySession: false,
  };
  const configured = emailOTP({
    storeOTP: "hashed",
    allowedAttempts: 3,
    disableSignUp: options.disableSignUp ?? true,
    sendVerificationOTP: (value) => {
      if (observed.failDelivery)
        return Promise.reject(new Error("private delivery failure"));
      observed.sent.push(value);
      return Promise.resolve();
    },
  });
  const plugin: BetterAuthPlugin = configured;
  const { auth, testUser } = await getTestInstance(
    {
      plugins: [
        ...(options.installed === false ? [] : [plugin]),
        twoFactor(),
        {
          id: "otp-method-probe",
          hooks: {
            before: [
              {
                matcher: (ctx) =>
                  ctx.path === "/sign-in/email-otp" ||
                  ctx.path === "/email-otp/send-verification-otp",
                handler: createAuthMiddleware(async (ctx) => {
                  observed.calls.push(ctx.path);
                  observed.ambient.push(
                    ctx.headers?.get("cookie") ?? null,
                    ctx.headers?.get("authorization") ?? null,
                    ctx.headers?.get("dpop") ?? null,
                  );
                  if (observed.limit)
                    throw new APIError(
                      "TOO_MANY_REQUESTS",
                      { message: "private limit" },
                      { "retry-after": "30", "set-cookie": "private-cookie" },
                    );
                  if (observed.deny)
                    throw new APIError("FORBIDDEN", {
                      message: "private policy",
                    });
                  if (
                    observed.deliverySession &&
                    ctx.path === "/email-otp/send-verification-otp"
                  ) {
                    const user =
                      await ctx.context.internalAdapter.findUserByEmail(
                        (ctx.body as { email: string }).email,
                      );
                    if (user)
                      await ctx.context.internalAdapter.createSession(
                        user.user.id,
                      );
                  }
                }),
              },
            ],
            after: [
              {
                matcher: (ctx) => ctx.path === "/sign-in/email-otp",
                handler: createAuthMiddleware(async (ctx) => {
                  if (observed.revokeAfter && ctx.context.newSession)
                    await ctx.context.internalAdapter.deleteSession(
                      ctx.context.newSession.session.token,
                    );
                }),
              },
            ],
          },
          endpoints: {
            otpProbe: createAuthEndpoint(
              "/test-only/otp",
              {
                method: "POST",
                body: z.object({
                  action: z.enum(["send", "verify"]),
                  email: z.string(),
                  otp: z.string().optional(),
                  failCleanup: z.boolean().optional(),
                }),
              },
              async (ctx) => {
                const isolated = ctx.body.failCleanup
                  ? {
                      ...ctx,
                      context: {
                        ...ctx.context,
                        internalAdapter: {
                          ...ctx.context.internalAdapter,
                          deleteSession: () =>
                            Promise.reject(
                              new Error("private cleanup failure"),
                            ),
                        },
                      },
                    }
                  : ctx;
                return ctx.json(
                  ctx.body.action === "send"
                    ? await sendEmailOTP(isolated, { email: ctx.body.email })
                    : await authenticateWithEmailOTP(isolated, {
                        email: ctx.body.email,
                        otp: ctx.body.otp ?? "",
                      }),
                );
              },
            ),
          },
        },
      ],
    },
    { testWith, transaction: true },
  );
  const context = await auth.$context;
  await context.adapter.deleteMany({ model: "session", where: [] });
  const request = async (
    action: "send" | "verify",
    input: { email?: string; otp?: string; failCleanup?: boolean } = {},
  ) =>
    auth.handler(
      new Request(`${context.baseURL}/test-only/otp`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          cookie: "better-auth.session_token=ambient",
          authorization: "Bearer ambient",
          dpop: "ambient-proof",
        },
        body: JSON.stringify({ action, email: testUser.email, ...input }),
      }),
    );
  const send = (email?: string) => request("send", email ? { email } : {});
  const verify = (otp = observed.sent.at(-1)?.otp ?? "", email?: string) =>
    request("verify", { otp, ...(email ? { email } : {}) });
  return { auth, context, testUser, observed, request, send, verify };
}

async function fixture(
  testWith: "sqlite" | "postgres",
  requireEmailVerification = false,
) {
  const observed = {
    calls: 0,
    cookie: null as string | null,
    authorization: null as string | null,
    deny: false,
    limit: false,
    revokeAfter: false,
  };
  const { auth, testUser } = await getTestInstance(
    {
      emailAndPassword: { enabled: true, requireEmailVerification },
      plugins: [
        twoFactor(),
        {
          id: "password-method-probe",
          hooks: {
            before: [
              {
                matcher: (ctx) => ctx.path === "/sign-in/email",
                handler: createAuthMiddleware((ctx) => {
                  observed.calls++;
                  observed.cookie = ctx.headers?.get("cookie") ?? null;
                  observed.authorization =
                    ctx.headers?.get("authorization") ?? null;
                  if (observed.limit)
                    throw new APIError(
                      "TOO_MANY_REQUESTS",
                      { message: "limited" },
                      { "retry-after": "30", "set-cookie": "do-not-forward" },
                    );
                  if (observed.deny)
                    throw new APIError("FORBIDDEN", {
                      message: "Additional verification required",
                    });
                  return Promise.resolve();
                }),
              },
            ],
            after: [
              {
                matcher: (ctx) => ctx.path === "/sign-in/email",
                handler: createAuthMiddleware(async (ctx) => {
                  if (observed.revokeAfter && ctx.context.newSession)
                    await ctx.context.internalAdapter.deleteSession(
                      ctx.context.newSession.session.token,
                    );
                }),
              },
            ],
          },
          endpoints: {
            passwordProbe: createAuthEndpoint(
              "/test-only/password",
              {
                method: "POST",
                body: z.object({
                  email: z.string(),
                  password: z.string(),
                  failCleanup: z.boolean().optional(),
                }),
              },
              async (ctx) => {
                const isolated = ctx.body.failCleanup
                  ? {
                      ...ctx,
                      context: {
                        ...ctx.context,
                        internalAdapter: {
                          ...ctx.context.internalAdapter,
                          deleteSession: () =>
                            Promise.reject(
                              new Error("injected-cleanup-failure"),
                            ),
                        },
                      },
                    }
                  : ctx;
                return ctx.json(
                  await authenticateWithPassword(isolated, {
                    email: ctx.body.email,
                    password: ctx.body.password,
                  }),
                );
              },
            ),
          },
        },
      ],
    },
    { testWith, transaction: true },
  );
  const context = await auth.$context;
  await context.adapter.deleteMany({ model: "session", where: [] });
  const login = (password = testUser.password, failCleanup = false) =>
    auth.api.passwordProbe({
      body: { email: testUser.email, password, failCleanup },
    });
  const sessions = () => context.adapter.findMany({ model: "session" });
  return { auth, testUser, context, observed, login, sessions };
}

for (const database of ["sqlite", "postgres"] as const) {
  describe.runIf(
    database === "sqlite"
      ? process.env.TEST_POSTGRES !== "true" &&
          Number(process.versions.node.split(".")[0]) >= 22
      : process.env.TEST_POSTGRES === "true",
  )(`First-party email OTP method (${database})`, () => {
    it("uses configured delivery and consuming authentication, suppresses ambient credentials and cleans sessions", async () => {
      const f = await otpFixture(database);
      expect(await (await f.send()).json()).toEqual({ kind: "requested" });
      expect(f.observed.sent).toHaveLength(1);
      expect(f.observed.sent[0]).toMatchObject({
        email: f.testUser.email,
        type: "sign-in",
      });
      const result = await f.verify();
      expect(result.status).toBe(200);
      expect(result.headers.get("set-cookie")).toBeNull();
      const body: unknown = await result.json();
      expect(body).toMatchObject({ kind: "authenticated", amr: ["otp"] });
      expect(body).not.toHaveProperty("token");
      expect(f.observed.calls).toEqual([
        "/email-otp/send-verification-otp",
        "/sign-in/email-otp",
      ]);
      expect(f.observed.ambient.every((value) => value === null)).toBe(true);
      expect(await f.context.adapter.count({ model: "session" })).toBe(0);
      expect(await (await f.verify()).json()).toEqual({ kind: "rejected" });
    });
    it("consumes an OTP once under concurrent submissions", async () => {
      const f = await otpFixture(database);
      await f.send();
      const results = await Promise.all([f.verify(), f.verify()]);
      const bodies = await Promise.all(
        results.map((response) => response.json() as Promise<{ kind: string }>),
      );
      expect(bodies.map((body) => body.kind).sort()).toEqual([
        "authenticated",
        "rejected",
      ]);
      expect(await f.context.adapter.count({ model: "session" })).toBe(0);
    });
    it("honors the configured OTP attempt limit and expiration", async () => {
      const f = await otpFixture(database);
      await f.send();
      for (let attempt = 0; attempt < 3; attempt++)
        expect(await (await f.verify("not-the-code")).json()).toEqual({
          kind: "rejected",
        });
      expect(await (await f.verify()).json()).not.toMatchObject({
        kind: "authenticated",
      });
      await f.send();
      await f.context.adapter.updateMany({
        model: "verification",
        where: [],
        update: { expiresAt: new Date(0) },
      });
      expect(await (await f.verify()).json()).toEqual({ kind: "rejected" });
      expect(await f.context.adapter.count({ model: "session" })).toBe(0);
    });
    it("does not let email OTP bypass a user's existing MFA requirement", async () => {
      const f = await otpFixture(database);
      await f.context.adapter.update({
        model: "user",
        where: [{ field: "email", value: f.testUser.email }],
        update: { twoFactorEnabled: true },
      });
      await f.send();
      expect(await (await f.verify()).json()).toEqual({
        kind: "browser-required",
      });
      expect(await f.context.adapter.count({ model: "session" })).toBe(0);
    });
    it("honors sign-up policy without disclosing an absent account", async () => {
      const f = await otpFixture(database);
      expect(await (await f.send("absent@example.test")).json()).toEqual({
        kind: "requested",
      });
      expect(f.observed.sent).toEqual([]);
      expect(
        await f.context.adapter.count({
          model: "user",
          where: [{ field: "email", value: "absent@example.test" }],
        }),
      ).toBe(0);
      const allowed = await otpFixture(database, { disableSignUp: false });
      await allowed.send("new@example.test");
      const response = await allowed.verify(undefined, "new@example.test");
      expect(await response.json()).toMatchObject({
        kind: "authenticated",
        amr: ["otp"],
      });
      expect(
        await allowed.context.adapter.findOne({
          model: "user",
          where: [{ field: "email", value: "new@example.test" }],
        }),
      ).toMatchObject({ emailVerified: true });
      expect(await allowed.context.adapter.count({ model: "session" })).toBe(0);
    });
    it("honors custom rejection and after-hook revocation", async () => {
      const f = await otpFixture(database);
      await f.send();
      f.observed.deny = true;
      expect(await (await f.verify()).json()).toEqual({
        kind: "browser-required",
      });
      f.observed.deny = false;
      f.observed.revokeAfter = true;
      expect(await (await f.verify()).json()).toEqual({
        kind: "browser-required",
      });
      expect(await f.context.adapter.count({ model: "session" })).toBe(0);
    });
    it.each(["send", "verify"] as const)(
      "preserves rate-limit guidance for %s without forwarding cookies",
      async (action) => {
        const f = await otpFixture(database);
        await f.send();
        f.observed.limit = true;
        const response = await f.request(action, {
          otp: f.observed.sent[0]!.otp,
        });
        expect(response.status).toBe(429);
        expect(response.headers.get("retry-after")).toBe("30");
        expect(response.headers.get("set-cookie")).toBeNull();
        expect(await f.context.adapter.count({ model: "session" })).toBe(0);
      },
    );
    it("cleans sessions created by delivery hooks even when delivery fails", async () => {
      const f = await otpFixture(database);
      f.observed.deliverySession = true;
      f.observed.failDelivery = true;
      const response = await f.send();
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({ kind: "requested" });
      expect(f.observed.sent).toEqual([]);
      expect(await f.context.adapter.count({ model: "session" })).toBe(0);
    });
    it("fails closed when cleanup fails or the email-OTP plugin is unavailable", async () => {
      const f = await otpFixture(database);
      await f.send();
      expect(
        (
          await f.request("verify", {
            otp: f.observed.sent[0]!.otp,
            failCleanup: true,
          })
        ).status,
      ).toBe(500);
      const missing = await otpFixture(database, { installed: false });
      expect((await missing.send()).status).toBe(500);
      expect((await missing.verify("123456")).status).toBe(500);
    });
  });
  describe.runIf(
    database === "sqlite"
      ? process.env.TEST_POSTGRES !== "true" &&
          Number(process.versions.node.split(".")[0]) >= 22
      : process.env.TEST_POSTGRES === "true",
  )(`First-party password method (${database})`, () => {
    it("invokes configured hooks, accepts the verified user, and removes temporary sessions", async () => {
      const f = await fixture(database);
      expect(await f.login()).toMatchObject({
        kind: "authenticated",
        amr: ["pwd"],
      });
      expect(f.observed.calls).toBe(1);
      expect(await f.sessions()).toEqual([]);
      expect(await f.login("incorrect-password")).toEqual({ kind: "rejected" });
      expect(await f.sessions()).toEqual([]);
    });
    it("does not reuse ambient credentials or return Better Auth session cookies", async () => {
      const f = await fixture(database);
      const response = await f.auth.handler(
        new Request(`${f.context.baseURL}/test-only/password`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            cookie: "better-auth.session_token=ambient",
            authorization: "Bearer ambient",
            dpop: "outer-proof",
          },
          body: JSON.stringify({
            email: f.testUser.email,
            password: f.testUser.password,
          }),
        }),
      );
      expect(response.status).toBe(200);
      expect(response.headers.get("set-cookie")).toBeNull();
      const body: unknown = await response.json();
      expect(body).toMatchObject({ kind: "authenticated" });
      expect(body).not.toHaveProperty("token");
      expect(f.observed.cookie).toBeNull();
      expect(f.observed.authorization).toBeNull();
      expect(await f.sessions()).toEqual([]);
    });
    it("preserves rate-limit guidance without forwarding authentication cookies", async () => {
      const f = await fixture(database);
      f.observed.limit = true;
      const response = await f.auth.handler(
        new Request(`${f.context.baseURL}/test-only/password`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            email: f.testUser.email,
            password: f.testUser.password,
          }),
        }),
      );
      expect(response.status).toBe(429);
      expect(response.headers.get("retry-after")).toBe("30");
      expect(response.headers.get("set-cookie")).toBeNull();
      expect(await f.sessions()).toEqual([]);
    });

    it("does not bypass two-factor authentication", async () => {
      const f = await fixture(database);
      await f.context.adapter.update({
        model: "user",
        where: [{ field: "email", value: f.testUser.email }],
        update: { twoFactorEnabled: true },
      });
      expect(await f.login()).toEqual({ kind: "browser-required" });
      expect(await f.sessions()).toEqual([]);
    });
    it("preserves email-verification and custom authentication policy", async () => {
      const f = await fixture(database, true);
      expect(await f.login()).toEqual({ kind: "browser-required" });
      expect(await f.sessions()).toEqual([]);
      const custom = await fixture(database);
      custom.observed.deny = true;
      expect(await custom.login()).toEqual({ kind: "browser-required" });
      expect(await custom.sessions()).toEqual([]);
    });
    it("does not accept a token that an after-hook revoked", async () => {
      const f = await fixture(database);
      f.observed.revokeAfter = true;
      expect(await f.login()).toEqual({ kind: "browser-required" });
      expect(await f.sessions()).toEqual([]);
    });
    it("fails rather than completing authentication when session cleanup fails", async () => {
      const f = await fixture(database);
      await expect(f.login(f.testUser.password, true)).rejects.toMatchObject({
        statusCode: 500,
        body: { error: "server_error" },
      });
    });
  });
}
