/** The few DER primitives SCEP's signed attributes need, which the ASN.1 schema classes do not model. */

function lengthBytes(length: number): number[] {
  if (length < 0x80) {
    return [length];
  }
  const bytes: number[] = [];
  for (let value = length; value > 0; value = Math.floor(value / 256)) {
    bytes.unshift(value % 256);
  }
  return [0x80 | bytes.length, ...bytes];
}

export function tlv(tag: number, content: Uint8Array): Uint8Array {
  return new Uint8Array([tag, ...lengthBytes(content.length), ...content]);
}

export const derPrintable = (value: string): Uint8Array =>
  tlv(0x13, new Uint8Array(Buffer.from(value, 'latin1')));
export const derOctet = (value: Uint8Array): Uint8Array => tlv(0x04, value);

const pad = (n: number): string => String(n).padStart(2, '0');

/** Encodes a time as a UTCTime (years 1950 to 2049), which every CMS implementation reads. */
export function derUtcTime(date: Date): Uint8Array {
  const text =
    `${pad(date.getUTCFullYear() % 100)}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}` +
    `${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}Z`;
  return tlv(0x17, new Uint8Array(Buffer.from(text, 'ascii')));
}

export interface Tlv {
  tag: number;
  content: Uint8Array;
  /** The bytes of the whole element, header included. */
  raw: Uint8Array;
}

/**
 * Reads one TLV from the start of `bytes`. Accepts BER indefinite lengths on constructed values,
 * which Bouncy Castle (jscep) uses for the outer structures; throws on anything malformed.
 */
export function readTlv(bytes: Uint8Array): Tlv {
  if (bytes.length < 2) {
    throw new Error('Truncated DER value.');
  }
  const tag = bytes[0];
  let length = bytes[1];
  let offset = 2;
  if (length === 0x80) {
    if ((tag & 0x20) === 0) {
      throw new Error('Indefinite length on a primitive value.');
    }
    let position = 2;
    while (!(bytes[position] === 0 && bytes[position + 1] === 0)) {
      if (position >= bytes.length) {
        throw new Error('Unterminated indefinite length.');
      }
      position += readTlv(bytes.subarray(position)).raw.length;
    }
    return {
      tag,
      content: bytes.subarray(2, position),
      raw: bytes.subarray(0, position + 2),
    };
  }
  if (length & 0x80) {
    const count = length & 0x7f;
    if (count === 0 || count > 4 || bytes.length < 2 + count) {
      throw new Error('Unsupported DER length.');
    }
    length = 0;
    for (let index = 0; index < count; index += 1) {
      length = length * 256 + bytes[2 + index];
    }
    offset = 2 + count;
  }
  if (bytes.length < offset + length) {
    throw new Error('Truncated DER value.');
  }
  return {
    tag,
    content: bytes.subarray(offset, offset + length),
    raw: bytes.subarray(0, offset + length),
  };
}

/** Parses a UTCTime or GeneralizedTime. */
export function parseTime(value: Tlv): Date {
  const text = Buffer.from(value.content).toString('ascii');
  const match = /^(\d{2}|\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/.exec(text);
  if (!match || (value.tag !== 0x17 && value.tag !== 0x18)) {
    throw new Error('Unsupported time.');
  }
  const year =
    match[1].length === 2 ? (Number(match[1]) >= 50 ? 1900 : 2000) + Number(match[1]) : Number(match[1]);
  return new Date(
    Date.UTC(
      year,
      Number(match[2]) - 1,
      Number(match[3]),
      Number(match[4]),
      Number(match[5]),
      Number(match[6] ?? '0'),
    ),
  );
}

/** The elements directly inside a constructed value, in order. */
export function children(content: Uint8Array): Tlv[] {
  const result: Tlv[] = [];
  let rest = content;
  while (rest.length > 0) {
    const element = readTlv(rest);
    result.push(element);
    rest = rest.subarray(element.raw.length);
  }
  return result;
}
