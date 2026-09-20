import type { GenericEndpointContext } from "@better-auth/core";
import {
  getOAuthProviderApi,
  type OAuthOptions,
} from "@better-auth/oauth-provider";

/** First-party policy must observe current registration changes, including
 * when ordinary OAuth traffic has warmed the host's trusted-client cache.
 * A fresh options object avoids that cache's options-keyed identity; an empty
 * set prevents repopulation. Keep the public API's discovery and schema support.
 */
export function getFirstPartyOAuthApi(
  ctx: GenericEndpointContext,
  options: OAuthOptions<string[]>,
  grantType?: Parameters<typeof getOAuthProviderApi>[2],
) {
  return getOAuthProviderApi(
    ctx,
    { ...options, cachedTrustedClients: new Set() },
    grantType,
  );
}
