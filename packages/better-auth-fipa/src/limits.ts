/**
 * Maximum portable length for an indexed provider application identity.
 * Better Auth generates 255-character indexed strings for adapters such as
 * MySQL, so the transport and provider contracts share the same bound.
 */
export const MAX_APPLICATION_ID_LENGTH = 255;
