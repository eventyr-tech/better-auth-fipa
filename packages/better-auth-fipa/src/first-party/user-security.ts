import type { GenericEndpointContext } from "@better-auth/core";
import type { BetterAuthOptions, BetterAuthPlugin } from "better-auth";
import { APIError } from "better-auth/api";
import { randomBytes } from "node:crypto";
import { equalBytes, hmacSha256 } from "../protocol/crypto.js";

const EPOCH = "firstPartySecurityEpoch";
const newEpoch = () => randomBytes(32).toString("base64url");
const epochField = {
  type: "string",
  required: false,
  input: false,
  returned: false,
  defaultValue: newEpoch,
} as const;

/** Private version fields use supported BA schema/hooks. These are not API
 * inputs and are not returned in user/account responses. A second change back
 * to the old value must not resurrect an authorization issued before it.
 */
export const userSecuritySchema = {
  user: { fields: { [EPOCH]: epochField } },
  account: { fields: { [EPOCH]: epochField } },
} satisfies NonNullable<BetterAuthPlugin["schema"]>;

export const userSecurityHooks = {
  user: {
    update: {
      before: (data) =>
        Promise.resolve({
          data: changed(data, [
            "email",
            "emailVerified",
            "twoFactorEnabled",
            "banned",
            "banExpires",
            "role",
            EPOCH,
          ]),
        }),
    },
  },
  account: {
    update: {
      before: (data) =>
        Promise.resolve({
          data: changed(data, [
            "password",
            "providerId",
            "accountId",
            "userId",
            EPOCH,
          ]),
        }),
    },
  },
} satisfies NonNullable<BetterAuthOptions["databaseHooks"]>;

function changed<T extends object>(
  data: T,
  fields: string[],
): T & { firstPartySecurityEpoch?: string } {
  return fields.some((field) => Object.hasOwn(data, field))
    ? { ...data, [EPOCH]: newEpoch() }
    : data;
}

interface SecurityUser {
  id: string;
  email: string;
  emailVerified: boolean;
  firstPartySecurityEpoch?: string | null;
  twoFactorEnabled?: boolean | null;
  banned?: boolean | null;
  role?: string | null;
}
interface SecurityAccount {
  id: string;
  providerId: string;
  accountId: string;
  password?: string | null;
  firstPartySecurityEpoch?: string | null;
}

/** Never cache this across operations. No password hash or raw email is stored
 * in an authorization/family; only this issuer-scoped, keyed digest is retained.
 * Unrelated display-name/image changes and OAuth access-token rotations are not
 * security-version changes. Arbitrary application policy needs explicit host
 * integration; raw database writes cannot synthesize a valid factor result.
 */
export async function userSecurityHash(
  ctx: Pick<GenericEndpointContext, "context">,
  userId: string,
): Promise<string> {
  const user = await ctx.context.adapter.findOne<SecurityUser>({
    model: "user",
    where: [{ field: "id", value: userId }],
  });
  if (!user || user.banned === true) throw invalid();
  const accounts: SecurityAccount[] = [];
  for (let offset = 0; ; offset += 100) {
    const page = await ctx.context.adapter.findMany<SecurityAccount>({
      model: "account",
      where: [{ field: "userId", value: userId }],
      sortBy: { field: "id", direction: "asc" },
      offset,
      limit: 100,
    });
    accounts.push(...page);
    if (page.length < 100) break;
  }
  return hmacSha256(
    ctx.context.secret,
    JSON.stringify([
      "first-party-user-security:v1",
      ctx.context.baseURL,
      user.id,
      user.email,
      user.emailVerified,
      user.firstPartySecurityEpoch ?? null,
      user.twoFactorEnabled ?? false,
      user.role ?? null,
      accounts.map((account) => [
        account.id,
        account.providerId,
        account.accountId,
        account.password ?? null,
        account.firstPartySecurityEpoch ?? null,
      ]),
    ]),
  );
}

export async function requireUserSecurity(
  ctx: Pick<GenericEndpointContext, "context">,
  userId: string,
  expected: string,
): Promise<void> {
  if (
    typeof expected !== "string" ||
    !/^[a-f0-9]{64}$/.test(expected) ||
    !equalBytes(
      Buffer.from(expected),
      Buffer.from(await userSecurityHash(ctx, userId)),
    )
  )
    throw invalid();
}

function invalid() {
  return new APIError("BAD_REQUEST", { error: "invalid_grant" });
}
