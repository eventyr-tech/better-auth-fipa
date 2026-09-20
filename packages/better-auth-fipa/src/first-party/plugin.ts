import { isAndroidHardwareProvider } from "../android/provider.js";
import type { BetterAuthPlugin } from "better-auth";
import {
  createNativeBrowserHook,
  nativeBrowserSessionHooks,
  createNativeBrowserCompleteEndpoint,
} from "./browser.js";
import { createNativeAdmissionEndpoints } from "./admission-endpoints.js";
import { createNativeChallengeEndpoint } from "./challenge-endpoint.js";
import { createNativeLifecycleEndpoints } from "./lifecycle-endpoints.js";
import { userSecurityHooks } from "./user-security.js";
import { firstPartyStateSchema } from "./state-schema.js";
import {
  createNativeTokenHook,
  type NativeTokenOptions,
} from "./token-lifecycle.js";
import { requireFirstPartyTransactions } from "./transaction.js";
import { createLegacyChallengeAdapter } from "./legacy-v1/adapter.js";
import { legacySessionSchema } from "./legacy-v1/session.js";
import { retireFirstPartyForUser } from "./public-retirement.js";

/** Native composition with an explicitly selected, temporary legacy adapter. */
export function createNativeFirstPartyPlugin(options: NativeTokenOptions) {
  const legacy = options.legacyCompatibility
    ? createLegacyChallengeAdapter(options, options.legacyCompatibility)
    : undefined;
  return {
    id: "device-attestation-first-party",
    schema: {
      ...firstPartyStateSchema,
      ...(legacy ? legacySessionSchema : {}),
    },
    init(context) {
      requireFirstPartyTransactions(context.adapter);
      if (
        context.options.secondaryStorage &&
        context.options.verification?.storeInDatabase !== true
      )
        throw new TypeError(
          "First-party authentication requires verification.storeInDatabase: true when secondaryStorage is configured.",
        );
      if (
        options.emailOTP &&
        context.options.plugins?.filter((plugin) => plugin.id === "email-otp")
          .length !== 1
      )
        throw new TypeError(
          "Native email OTP requires exactly one configured email-otp plugin.",
        );
      for (const id of [
        "oauth-provider",
        ...(legacy ||
        options.applications.some(
          (app) => !isAndroidHardwareProvider(app.provider),
        )
          ? ["device-attestation"]
          : []),
      ])
        if (!context.options.plugins?.some((plugin) => plugin.id === id))
          throw new TypeError(
            `First-party authentication requires the ${id} plugin.`,
          );
      return {
        options: {
          databaseHooks: {
            ...userSecurityHooks,
            user: {
              ...userSecurityHooks.user,
              // Apple/legacy composition delegates from its existing hook.
              // Android-only composition has no low-level Apple plugin.
              ...(!context.options.plugins?.some(
                (plugin) => plugin.id === "device-attestation",
              )
                ? {
                    delete: {
                      before: async (user, hookContext) => {
                        if (
                          (await context.options.databaseHooks?.user?.delete?.before?.(
                            user,
                            hookContext,
                          )) === false
                        )
                          return false;
                        await retireFirstPartyForUser(context, user.id);
                      },
                    },
                  }
                : {}),
            },
            ...(options.browser ? nativeBrowserSessionHooks : {}),
          },
        },
      };
    },
    endpoints: {
      firstPartyAuthorizationChallenge: createNativeChallengeEndpoint(
        options,
        legacy,
      ),
      ...createNativeAdmissionEndpoints(options.applications),
      ...createNativeLifecycleEndpoints(options),
      firstPartyBrowserComplete: createNativeBrowserCompleteEndpoint(options),
    },
    hooks: {
      before: [
        createNativeTokenHook(options, legacy?.policies),
        createNativeBrowserHook(options),
      ],
    },
    rateLimit: [
      {
        window: 60,
        max: 10,
        pathMatcher: (path) =>
          path === "/first-party/android/key-challenge" ||
          path === "/first-party/android/register",
      },
      {
        window: 60,
        max: 30,
        pathMatcher: (path) => path === "/first-party/attestation/challenge",
      },
      {
        window: 60,
        max: 20,
        pathMatcher: (path) => path === "/first-party/attestation/verify",
      },
      {
        window: 60,
        max: 10,
        pathMatcher: (path) => path === "/first-party/authorization-challenge",
      },
      {
        window: 60,
        max: 20,
        pathMatcher: (path) =>
          path === "/first-party/logout" ||
          path === "/first-party/retire" ||
          path === "/first-party/browser/complete",
      },
    ],
  } satisfies BetterAuthPlugin;
}
