import { MAX_MESSAGE_LENGTH, MAX_PADDED_MESSAGE_BYTES } from '@alparts/shared';

// An invalid UTF-8 lead byte unambiguously separates this versioned, encrypted
// payload from historical UTF-8 text. The whole payload is authenticated by GCM.
const magic = Uint8Array.of(0xff, 0x41, 0x4c, 0x50, 0x41, 0x44, 0, 1);
const headerBytes = magic.length + 4;
export function padMessage(content: string): Uint8Array<ArrayBuffer> {
  const text = new TextEncoder().encode(content);
  if (content.length > MAX_MESSAGE_LENGTH || text.length > MAX_MESSAGE_LENGTH * 4) throw new Error('MESSAGE_TOO_LONG');
  const size = Math.max(1024, 2 ** Math.ceil(Math.log2(headerBytes + text.length)));
  if (size > MAX_PADDED_MESSAGE_BYTES) throw new Error('MESSAGE_TOO_LONG');
  const padded = new Uint8Array(size);
  padded.set(magic);
  new DataView(padded.buffer).setUint32(magic.length, text.length);
  padded.set(text, headerBytes);
  return padded;
}

export function unpadMessage(bytes: Uint8Array): string {
  const decoder = new TextDecoder('utf-8', { fatal: true });
  if (bytes[0] !== magic[0]) return decoder.decode(bytes); // Historical text.
  if (bytes.length < 1024 || bytes.length > MAX_PADDED_MESSAGE_BYTES
    || (bytes.length & (bytes.length - 1)) !== 0
    || !magic.every((byte, index) => bytes[index] === byte)) throw new Error('INVALID_MESSAGE_PADDING');
  const size = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(magic.length);
  if (size > MAX_MESSAGE_LENGTH * 4 || headerBytes + size > bytes.length
    || bytes.subarray(headerBytes + size).some((byte) => byte !== 0)) throw new Error('INVALID_MESSAGE_PADDING');
  const text = decoder.decode(bytes.subarray(headerBytes, headerBytes + size));
  if (text.length > MAX_MESSAGE_LENGTH) throw new Error('INVALID_MESSAGE_PADDING');
  return text;
}
