import { rejection } from "../errors.js";

/** Strict, bounded DER reader for Android's KeyDescription extension. This
 * parses claims only; they become evidence only after certificate validation. */
interface Element {
  cls: number;
  tag: number;
  constructed: boolean;
  bytes: Buffer;
  encoded: Buffer;
  children: Element[];
}
export interface AndroidAuthorizationList {
  integers: Map<number, bigint>;
  sets: Map<number, bigint[]>;
  flags: Set<number>;
  octets: Map<number, Buffer>;
  rootOfTrust?: {
    verifiedBootKey: Buffer;
    deviceLocked: boolean;
    verifiedBootState: number;
    verifiedBootHash?: Buffer;
  };
}
export interface AndroidKeyDescription {
  attestationVersion: number;
  attestationSecurityLevel: number;
  keymasterVersion: number;
  keymasterSecurityLevel: number;
  challenge: Buffer;
  uniqueId: Buffer;
  software: AndroidAuthorizationList;
  hardware: AndroidAuthorizationList;
  application?: {
    packages: { name: string; version: bigint }[];
    signingCertificateDigests: string[];
  };
}

const integerTags = new Set([
  2, 3, 8, 10, 11, 200, 400, 401, 402, 405, 504, 505, 701, 702, 705, 706, 718,
  719,
]);
const setTags = new Set([1, 4, 5, 6, 203]);
const flagTags = new Set([7, 303, 305, 503, 506, 507, 508, 509, 600, 703, 720]);
const octetTags = new Set([
  601, 709, 710, 711, 712, 713, 714, 715, 716, 717, 723, 724,
]);

export function parseAndroidKeyDescription(
  bytes: Uint8Array,
): AndroidKeyDescription {
  const root = parseDer(bytes);
  const fields = children(root, 16);
  if (fields.length !== 8) throw invalid();
  const software = authorization(fields[6]!);
  const hardware = authorization(fields[7]!);
  const softwareTags = tags(software);
  if (tags(hardware).some((tag) => softwareTags.includes(tag))) throw invalid();
  const application = software.octets.get(709) ?? hardware.octets.get(709);
  return {
    attestationVersion: smallInteger(fields[0]!),
    attestationSecurityLevel: smallInteger(fields[1]!, 10),
    keymasterVersion: smallInteger(fields[2]!),
    keymasterSecurityLevel: smallInteger(fields[3]!, 10),
    challenge: octets(fields[4]!),
    uniqueId: octets(fields[5]!),
    software,
    hardware,
    ...(application ? { application: parseApplication(application) } : {}),
  };
}

function authorization(element: Element): AndroidAuthorizationList {
  const result: AndroidAuthorizationList = {
    integers: new Map(),
    sets: new Map(),
    flags: new Set(),
    octets: new Map(),
  };
  let previous = -1;
  for (const field of children(element, 16)) {
    if (
      field.cls !== 2 ||
      !field.constructed ||
      field.tag <= previous ||
      field.children.length !== 1
    )
      throw invalid();
    previous = field.tag;
    const value = field.children[0]!;
    if (integerTags.has(field.tag))
      result.integers.set(field.tag, integer(value));
    else if (setTags.has(field.tag)) {
      const values = children(value, 17).map((entry) => integer(entry));
      if (
        !values.length ||
        values.length > 16 ||
        new Set(values).size !== values.length
      )
        throw invalid();
      result.sets.set(field.tag, values);
    } else if (flagTags.has(field.tag)) {
      primitive(value, 5);
      if (value.bytes.length) throw invalid();
      result.flags.add(field.tag);
    } else if (octetTags.has(field.tag))
      result.octets.set(field.tag, octets(value));
    else if (field.tag === 704) {
      const root = children(value, 16);
      if (root.length !== 3 && root.length !== 4) throw invalid();
      primitive(root[1]!, 1);
      if (root[1]!.bytes.length !== 1 || ![0, 255].includes(root[1]!.bytes[0]!))
        throw invalid();
      result.rootOfTrust = {
        verifiedBootKey: octets(root[0]!),
        deviceLocked: root[1]!.bytes[0] === 255,
        verifiedBootState: smallInteger(root[2]!, 10),
        ...(root[3] ? { verifiedBootHash: octets(root[3]) } : {}),
      };
    } else throw invalid(); // New authorization semantics require a reviewed parser update.
  }
  return result;
}
function tags(list: AndroidAuthorizationList) {
  return [
    ...list.integers.keys(),
    ...list.sets.keys(),
    ...list.flags,
    ...list.octets.keys(),
    ...(list.rootOfTrust ? [704] : []),
  ];
}
function parseApplication(bytes: Buffer) {
  const fields = children(parseDer(bytes), 16);
  if (fields.length !== 2) throw invalid();
  const packages = children(fields[0]!, 17).map((entry) => {
    const values = children(entry, 16);
    if (values.length !== 2) throw invalid();
    const nameBytes = octets(values[0]!);
    if (
      nameBytes.length > 255 ||
      !/^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$/.test(
        nameBytes.toString("ascii"),
      ) ||
      !nameBytes.equals(Buffer.from(nameBytes.toString("ascii"), "ascii"))
    )
      throw invalid();
    return { name: nameBytes.toString("ascii"), version: integer(values[1]!) };
  });
  const signingCertificateDigests = children(fields[1]!, 17).map((entry) => {
    const value = octets(entry);
    if (value.length !== 32) throw invalid();
    return value.toString("base64url");
  });
  if (
    !packages.length ||
    packages.length > 16 ||
    new Set(packages.map((entry) => entry.name)).size !== packages.length ||
    !signingCertificateDigests.length ||
    signingCertificateDigests.length > 8 ||
    new Set(signingCertificateDigests).size !== signingCertificateDigests.length
  )
    throw invalid();
  return { packages, signingCertificateDigests };
}
function children(element: Element, tag: number) {
  if (element.cls !== 0 || element.tag !== tag || !element.constructed)
    throw invalid();
  return element.children;
}
function primitive(element: Element, tag: number) {
  if (element.cls !== 0 || element.tag !== tag || element.constructed)
    throw invalid();
}
function octets(element: Element) {
  primitive(element, 4);
  return Buffer.from(element.bytes);
}
function integer(element: Element, tag = 2): bigint {
  primitive(element, tag);
  const bytes = element.bytes;
  if (
    !bytes.length ||
    bytes.length > 9 ||
    bytes[0]! >= 128 ||
    (bytes.length > 1 && bytes[0] === 0 && bytes[1]! < 128)
  )
    throw invalid();
  let value = 0n;
  for (const byte of bytes) value = value * 256n + BigInt(byte);
  if (value > 0xffff_ffff_ffff_ffffn) throw invalid();
  return value;
}
function smallInteger(element: Element, tag = 2) {
  const value = integer(element, tag);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw invalid();
  return Number(value);
}
function parseDer(input: Uint8Array): Element {
  if (!input.length || input.length > 16_384) throw invalid();
  const bytes = Buffer.from(input);
  let count = 0;
  function read(
    offset: number,
    limit: number,
    depth: number,
  ): { element: Element; end: number } {
    if (++count > 512 || depth > 8 || offset >= limit) throw invalid();
    const start = offset;
    const first = bytes[offset++]!;
    const cls = first >>> 6;
    const constructed = (first & 32) !== 0;
    let tag = first & 31;
    if (tag === 31) {
      tag = 0;
      let octets = 0;
      for (;;) {
        if (offset >= limit || ++octets > 3) throw invalid();
        const byte = bytes[offset++]!;
        if (octets === 1 && (byte & 127) === 0) throw invalid();
        tag = tag * 128 + (byte & 127);
        if (byte < 128) break;
      }
      if (tag < 31) throw invalid();
    }
    if (offset >= limit) throw invalid();
    let length = bytes[offset++]!;
    if (length >= 128) {
      const width = length & 127;
      if (!width || width > 3 || offset + width > limit || bytes[offset] === 0)
        throw invalid();
      length = 0;
      for (let n = 0; n < width; n++) length = length * 256 + bytes[offset++]!;
      if (length < 128) throw invalid();
    }
    const end = offset + length;
    if (end > limit) throw invalid();
    const values: Element[] = [];
    if (constructed) {
      let at = offset;
      while (at < end) {
        const nested = read(at, end, depth + 1);
        if (
          cls === 0 &&
          tag === 17 &&
          values.length &&
          Buffer.compare(values.at(-1)!.encoded, nested.element.encoded) >= 0
        )
          throw invalid();
        values.push(nested.element);
        at = nested.end;
      }
    }
    return {
      element: {
        cls,
        tag,
        constructed,
        bytes: bytes.subarray(offset, end),
        encoded: bytes.subarray(start, end),
        children: values,
      },
      end,
    };
  }
  const parsed = read(0, bytes.length, 0);
  if (parsed.end !== bytes.length) throw invalid();
  return parsed.element;
}
function invalid() {
  return rejection("certificate-chain", "invalid_android_key_description");
}
