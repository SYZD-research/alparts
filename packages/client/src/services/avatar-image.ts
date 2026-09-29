export const AVATAR_SIZE = 256;
export const MAX_AVATAR_SOURCE_BYTES = 5 * 1024 * 1024;
export const MAX_AVATAR_UPLOAD_BYTES = 320 * 1024;
const ACCEPTED_TYPES = new Set(['image/png', 'image/jpeg', 'image/webp']);

export class AvatarImageError extends Error {
  constructor(readonly reason: 'type' | 'size' | 'decode' | 'encode') {
    super(`AVATAR_${reason.toUpperCase()}`);
    this.name = 'AvatarImageError';
  }
}

/** Checks and decodes the chosen file so a part of it can be picked. */
export async function decodeAvatarSource(file: File): Promise<ImageBitmap> {
  if (!ACCEPTED_TYPES.has(file.type)) throw new AvatarImageError('type');
  if (file.size > MAX_AVATAR_SOURCE_BYTES) throw new AvatarImageError('size');
  try {
    return await createImageBitmap(file);
  } catch {
    throw new AvatarImageError('decode');
  }
}

/**
 * Redraws the chosen square into a fresh 256x256 PNG. Only pixels survive:
 * EXIF (including location), colour profiles, text chunks and any crafted
 * file structure of the original are left behind.
 */
export async function renderAvatar(bitmap: ImageBitmap, crop: { x: number; y: number; side: number }): Promise<Blob> {
  const canvas = document.createElement('canvas');
  canvas.width = AVATAR_SIZE;
  canvas.height = AVATAR_SIZE;
  const context = canvas.getContext('2d');
  if (!context) throw new AvatarImageError('encode');
  context.imageSmoothingQuality = 'high';
  context.drawImage(bitmap, crop.x, crop.y, crop.side, crop.side, 0, 0, AVATAR_SIZE, AVATAR_SIZE);
  const blob = await new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, 'image/png'));
  if (!blob || blob.size > MAX_AVATAR_UPLOAD_BYTES) throw new AvatarImageError('encode');
  return blob;
}
