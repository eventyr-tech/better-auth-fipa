import {
  createDpopProofError,
  verifyDpopProof,
  type DpopReplayStore,
  type VerifiedDpopProof,
} from "@better-auth/core/oauth2";

export interface FirstPartyDpopInput {
  headers: Headers;
  /** The externally configured endpoint URL, never an untrusted forwarded host. */
  endpointUrl: string;
  method: string;
  /** Required: production callers supply the shared database replay store. */
  replayStore: DpopReplayStore;
  /** Taken from server-owned continuation/code/credential state, when present. */
  expectedJkt?: string;
  /** A request parameter is only a consistency check, never proof of possession. */
  suppliedJkt?: string;
  /** Resource requests must bind the proof to the exact access token (ath). */
  accessToken?: string;
  nowSeconds?: number;
}

/** Verifies the mandatory ES256 proof before any first-party account work. */
export async function verifyFirstPartyDpop(
  input: FirstPartyDpopInput,
): Promise<VerifiedDpopProof> {
  const proofJwt = input.headers.get("dpop");
  if (!proofJwt || proofJwt.length > 8192) {
    throw createDpopProofError(
      "invalid_dpop_proof",
      "A bounded DPoP proof is required.",
    );
  }
  const proof = await verifyDpopProof({
    proofJwt,
    method: input.method,
    url: input.endpointUrl,
    replayStore: input.replayStore,
    signingAlgorithms: ["ES256"],
    proofMaxAgeSeconds: 60,
    ...(input.accessToken === undefined
      ? {}
      : { accessToken: input.accessToken }),
    ...(input.expectedJkt !== undefined
      ? { expectedJkt: input.expectedJkt }
      : {}),
    ...(input.nowSeconds !== undefined ? { nowSeconds: input.nowSeconds } : {}),
  });
  if (input.suppliedJkt !== undefined && input.suppliedJkt !== proof.jkt) {
    throw createDpopProofError(
      "invalid_dpop_proof",
      "The supplied thumbprint conflicts with the proof.",
    );
  }
  return proof;
}
