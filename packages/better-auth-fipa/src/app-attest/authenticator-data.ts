import { decodeSingleCbor } from "../cbor/decode.js";
import { rejection } from "../errors.js";

const RP_ID_HASH_BYTES = 32;
const FLAGS_BYTES = 1;
const COUNTER_BYTES = 4;
const FIXED_BYTES = RP_ID_HASH_BYTES + FLAGS_BYTES + COUNTER_BYTES;
const AAGUID_BYTES = 16;
const CREDENTIAL_LENGTH_BYTES = 2;

export const AUTHENTICATOR_DATA_FLAGS = {
  AT: 0x40,
  ED: 0x80,
} as const;

export interface ParsedAuthenticatorData {
  raw: Buffer;
  rpIdHash: Buffer;
  flags: number;
  counter: number;
  attestedCredentialData?: {
    aaguid: Buffer;
    credentialId: Buffer;
    credentialPublicKey: unknown;
    credentialPublicKeyBytes: Buffer;
  };
  extensions?: unknown;
  extensionBytes?: Buffer;
}

export function parseAuthenticatorData(
  input: Uint8Array,
  options: {
    mode: "attestation" | "assertion";
    maxBytes: number;
    maxCborDepth?: number;
    allowUnflaggedExtensions?: boolean;
  },
): ParsedAuthenticatorData {
  const raw = Buffer.from(input);
  if (raw.length < FIXED_BYTES || raw.length > options.maxBytes) {
    throw rejection("authenticator-data", "invalid_authenticator_data_length", {
      authenticatorDataBytes: raw.length,
    });
  }

  const rpIdHash = raw.subarray(0, RP_ID_HASH_BYTES);
  const flags = raw[RP_ID_HASH_BYTES];
  if (flags === undefined) {
    throw rejection("authenticator-data", "missing_authenticator_flags");
  }

  const counter = raw.readUInt32BE(RP_ID_HASH_BYTES + FLAGS_BYTES);
  const hasAttestedCredentialData = (flags & AUTHENTICATOR_DATA_FLAGS.AT) !== 0;
  const hasExtensions = (flags & AUTHENTICATOR_DATA_FLAGS.ED) !== 0;

  if (options.mode === "attestation" && !hasAttestedCredentialData) {
    throw rejection("authenticator-data", "missing_attested_credential_data", {
      flags,
    });
  }

  let offset = FIXED_BYTES;
  let attestedCredentialData:
    ParsedAuthenticatorData["attestedCredentialData"] | undefined;

  // App Attest assertions use Apple's simplified authenticator-data profile.
  // Some production assertions set the WebAuthn AT bit even though the fixed
  // 37-byte assertion header is not followed by attested credential data. Only
  // registrations carry and parse that structure; assertion trailing bytes are
  // still required to be a single valid extension container below.
  if (options.mode === "attestation" && hasAttestedCredentialData) {
    const credentialHeaderEnd = offset + AAGUID_BYTES + CREDENTIAL_LENGTH_BYTES;
    if (credentialHeaderEnd > raw.length) {
      throw rejection("authenticator-data", "truncated_credential_header", {
        flags,
      });
    }

    const aaguid = raw.subarray(offset, offset + AAGUID_BYTES);
    offset += AAGUID_BYTES;
    const credentialIdLength = raw.readUInt16BE(offset);
    offset += CREDENTIAL_LENGTH_BYTES;

    if (credentialIdLength === 0 || offset + credentialIdLength > raw.length) {
      throw rejection("authenticator-data", "invalid_credential_id_length", {
        flags,
      });
    }

    const credentialId = raw.subarray(offset, offset + credentialIdLength);
    offset += credentialIdLength;

    const cose = decodeSingleCbor(raw.subarray(offset), {
      label: "credential_public_key",
      ...(options.maxCborDepth === undefined
        ? {}
        : { maxDepth: options.maxCborDepth }),
      allowTrailing: true,
    });
    offset += cose.length;

    attestedCredentialData = {
      aaguid: Buffer.from(aaguid),
      credentialId: Buffer.from(credentialId),
      credentialPublicKey: cose.value,
      credentialPublicKeyBytes: Buffer.from(cose.bytes),
    };
  }

  let extensions: unknown;
  let extensionBytes: Buffer | undefined;
  if (
    hasExtensions ||
    (options.allowUnflaggedExtensions === true && offset < raw.length)
  ) {
    if (offset >= raw.length) {
      throw rejection("authenticator-data", "missing_extension_data", {
        flags,
      });
    }

    const decodedExtensions = decodeSingleCbor(raw.subarray(offset), {
      label: "authenticator_extensions",
      ...(options.maxCborDepth === undefined
        ? {}
        : { maxDepth: options.maxCborDepth }),
    });
    extensions = decodedExtensions.value;
    extensionBytes = Buffer.from(decodedExtensions.bytes);
    offset += decodedExtensions.length;
  }

  if (offset !== raw.length) {
    throw rejection("authenticator-data", "unexpected_authenticator_data", {
      flags,
      authenticatorDataBytes: raw.length,
      extensionBytes: raw.length - offset,
    });
  }

  return {
    raw,
    rpIdHash: Buffer.from(rpIdHash),
    flags,
    counter,
    ...(attestedCredentialData === undefined ? {} : { attestedCredentialData }),
    ...(extensions === undefined ? {} : { extensions }),
    ...(extensionBytes === undefined ? {} : { extensionBytes }),
  };
}
