import type { AndroidKeyPolicy } from "../key-policy.js";

export const challenge = Buffer.alloc(32, 5);
export const signer = Buffer.alloc(32, 6);
export const secondSigner = Buffer.alloc(32, 7);
export const policy: AndroidKeyPolicy = {
  policyVersion: "android-key-v1",
  packageName: "io.example.mobile",
  signingCertificateSets: [[signer.toString("base64url")]],
  minimumVersionCode: "42",
  allowedSecurityLevels: ["tee", "strongbox"],
  minimumOsVersion: 130000,
  minimumOsPatchLevel: 202601,
  minimumVendorPatchLevel: 20260101,
  minimumBootPatchLevel: 20260101,
  requireUnlockedDevice: true,
};
export function der(tag: number | number[], content: Buffer) {
  const length =
    content.length < 128
      ? [content.length]
      : content.length < 256
        ? [129, content.length]
        : [130, content.length >> 8, content.length & 255];
  return Buffer.concat([
    Buffer.from(typeof tag === "number" ? [tag] : tag),
    Buffer.from(length),
    content,
  ]);
}
export function sequence(...values: Buffer[]) {
  return der(0x30, Buffer.concat(values));
}
export function set(...values: Buffer[]) {
  return der(0x31, Buffer.concat(values.sort((a, b) => Buffer.compare(a, b))));
}
export function octets(bytes: Buffer) {
  return der(4, bytes);
}
export function number(value: number | bigint, tag = 2) {
  let hex = BigInt(value).toString(16);
  if (hex.length % 2) hex = "0" + hex;
  let bytes = Buffer.from(hex, "hex");
  if (bytes[0]! >= 128) bytes = Buffer.concat([Buffer.from([0]), bytes]);
  return der(tag, bytes);
}
export function context(tag: number, value: Buffer) {
  if (tag < 31) return der(0xa0 | tag, value);
  const bytes = [tag & 127];
  while ((tag = Math.floor(tag / 128))) bytes.unshift((tag & 127) | 128);
  return der([0xbf, ...bytes], value);
}
export function application(
  packages = [{ name: "io.example.mobile", version: 42n }],
  signers = [signer],
) {
  return octets(
    sequence(
      set(
        ...packages.map((entry) =>
          sequence(octets(Buffer.from(entry.name)), number(entry.version)),
        ),
      ),
      set(...signers.map(octets)),
    ),
  );
}
export function boot(locked = true, state = 0, hash = Buffer.alloc(32, 9)) {
  return sequence(
    octets(Buffer.alloc(32, 8)),
    der(1, Buffer.from([locked ? 255 : 0])),
    number(state, 10),
    octets(hash),
  );
}
export function model() {
  return {
    version: 300,
    keymaster: 300,
    attestationLevel: 1,
    keyLevel: 1,
    challenge,
    uniqueId: Buffer.alloc(0),
    software: new Map([
      [509, der(5, Buffer.alloc(0))],
      [709, application()],
    ]),
    hardware: new Map([
      [1, set(number(2), number(3))],
      [2, number(3)],
      [3, number(256)],
      [5, set(number(4))],
      [10, number(1)],
      [503, der(5, Buffer.alloc(0))],
      [702, number(0)],
      [704, boot()],
      [705, number(150000)],
      [706, number(202609)],
      [718, number(20260905)],
      [719, number(20260905)],
    ]),
  };
}
export type Model = ReturnType<typeof model>;
export function encode(value = model()) {
  const list = (values: Map<number, Buffer>) =>
    sequence(
      ...Array.from(values)
        .sort(([a], [b]) => a - b)
        .map(([tag, value]) => context(tag, value)),
    );
  return sequence(
    number(value.version),
    number(value.attestationLevel, 10),
    number(value.keymaster),
    number(value.keyLevel, 10),
    octets(value.challenge),
    octets(value.uniqueId),
    list(value.software),
    list(value.hardware),
  );
}
