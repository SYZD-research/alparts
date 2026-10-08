export const ATTACHMENT_IMAGE_PREVIEW_MAX_BYTES = 25 * 1024 * 1024;
export const ATTACHMENT_IMAGE_PREVIEW_HEADER_BYTES = 64;

const SAFE_RASTER_IMAGE_MIME_TYPES = new Set([
  'image/avif',
  'image/gif',
  'image/jpeg',
  'image/png',
  'image/webp',
]);

/**
 * Inline previews deliberately exclude SVG and other active/document formats.
 * Only browser-decoded raster image types are eligible.
 */
export function isPreviewableImageMimeType(mimeType: string): boolean {
  return SAFE_RASTER_IMAGE_MIME_TYPES.has(mimeType.trim().toLowerCase());
}

/** The allowlisted spelling of a previewable MIME type, or an empty string. */
export function previewImageMimeType(mimeType: string): string {
  const normalized = mimeType.trim().toLowerCase();
  return [...SAFE_RASTER_IMAGE_MIME_TYPES].find((type) => type === normalized) ?? '';
}

export function canPreviewImage(mimeType: string, sizeBytes: number): boolean {
  return Number.isSafeInteger(sizeBytes)
    && sizeBytes > 0
    && sizeBytes <= ATTACHMENT_IMAGE_PREVIEW_MAX_BYTES
    && isPreviewableImageMimeType(mimeType);
}

function startsWith(bytes: Uint8Array, signature: number[], offset = 0): boolean {
  return bytes.byteLength >= offset + signature.length
    && signature.every((value, index) => bytes[offset + index] === value);
}

function asciiAt(bytes: Uint8Array, offset: number, expected: string): boolean {
  return startsWith(bytes, [...expected].map((character) => character.charCodeAt(0)), offset);
}

/**
 * Confirm that decrypted/file bytes really match the claimed raster MIME type.
 * This prevents a renamed, empty, or malformed file from being rendered as a
 * broken image element merely because its extension supplied an image MIME.
 */
export function matchesPreviewImageSignature(mimeType: string, bytes: Uint8Array): boolean {
  switch (mimeType.trim().toLowerCase()) {
    case 'image/png':
      return startsWith(bytes, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    case 'image/jpeg':
      return startsWith(bytes, [0xff, 0xd8, 0xff]);
    case 'image/gif':
      return asciiAt(bytes, 0, 'GIF87a') || asciiAt(bytes, 0, 'GIF89a');
    case 'image/webp':
      return asciiAt(bytes, 0, 'RIFF') && asciiAt(bytes, 8, 'WEBP');
    case 'image/avif': {
      if (!asciiAt(bytes, 4, 'ftyp')) return false;
      for (let offset = 8; offset + 4 <= bytes.byteLength; offset += 4) {
        if (asciiAt(bytes, offset, 'avif') || asciiAt(bytes, offset, 'avis')) return true;
      }
      return false;
    }
    default:
      return false;
  }
}
