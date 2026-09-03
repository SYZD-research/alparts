import { describe, expect, it } from 'vitest';
import {
  ATTACHMENT_IMAGE_PREVIEW_MAX_BYTES,
  canPreviewImage,
  isPreviewableImageMimeType,
  matchesPreviewImageSignature,
} from './attachment-preview';

describe('attachment image preview policy', () => {
  it('allows bounded raster images and excludes active SVG content', () => {
    expect(canPreviewImage('image/png', 1024)).toBe(true);
    expect(canPreviewImage('IMAGE/JPEG', 1024)).toBe(true);
    expect(isPreviewableImageMimeType('image/svg+xml')).toBe(false);
    expect(canPreviewImage('image/svg+xml', 1024)).toBe(false);
  });

  it('keeps automatic preview memory bounded', () => {
    expect(canPreviewImage('image/webp', ATTACHMENT_IMAGE_PREVIEW_MAX_BYTES)).toBe(true);
    expect(canPreviewImage('image/webp', ATTACHMENT_IMAGE_PREVIEW_MAX_BYTES + 1)).toBe(false);
    expect(canPreviewImage('image/png', Number.NaN)).toBe(false);
    expect(canPreviewImage('image/png', 0)).toBe(false);
  });

  it('requires the actual bytes to match the claimed image type', () => {
    expect(matchesPreviewImageSignature('image/png', new Uint8Array([
      0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
    ]))).toBe(true);
    expect(matchesPreviewImageSignature('image/jpeg', new Uint8Array([0xff, 0xd8, 0xff, 0xe0]))).toBe(true);
    expect(matchesPreviewImageSignature('image/gif', new TextEncoder().encode('GIF89a'))).toBe(true);
    expect(matchesPreviewImageSignature('image/webp', new TextEncoder().encode('RIFF0000WEBP'))).toBe(true);
    expect(matchesPreviewImageSignature('image/avif', new Uint8Array([
      0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70,
      0x61, 0x76, 0x69, 0x66, 0x00, 0x00, 0x00, 0x00,
    ]))).toBe(true);
    expect(matchesPreviewImageSignature('image/png', new TextEncoder().encode('not an image'))).toBe(false);
  });
});
