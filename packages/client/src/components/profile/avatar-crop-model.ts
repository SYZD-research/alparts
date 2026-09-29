/**
 * Geometry for choosing the part of a picture that becomes the avatar.
 *
 * Everything is in editor pixels: the picture is drawn at `imageX/imageY`
 * with `displayScale()`, and the square frame marks what will be kept. Every
 * operation keeps two rules: the frame stays inside the editor, and the
 * picture always covers the whole frame (the avatar never has empty edges).
 */
export const CROP_STAGE = 288;
export const MIN_FRAME = 48;
export const MAX_ZOOM = 8;

export interface SourceSize {
  width: number;
  height: number;
}

export interface CropState {
  /** 1 shows the whole picture inside the editor. */
  zoom: number;
  imageX: number;
  imageY: number;
  frameX: number;
  frameY: number;
  frameSize: number;
}

export type CropCorner = 'nw' | 'ne' | 'sw' | 'se';

export interface SourceCrop {
  x: number;
  y: number;
  side: number;
}

const clamp = (value: number, low: number, high: number) => Math.min(Math.max(value, low), high);

export function displayScale(source: SourceSize, zoom: number): number {
  return (CROP_STAGE / Math.max(source.width, source.height)) * zoom;
}

function displayed(source: SourceSize, state: CropState) {
  const scale = displayScale(source, state.zoom);
  return { scale, width: source.width * scale, height: source.height * scale };
}

/** Where the frame may be: the part of the picture that is inside the editor. */
function frameBounds(source: SourceSize, state: CropState) {
  const { width, height } = displayed(source, state);
  return {
    left: Math.max(0, state.imageX),
    top: Math.max(0, state.imageY),
    right: Math.min(CROP_STAGE, state.imageX + width),
    bottom: Math.min(CROP_STAGE, state.imageY + height),
  };
}

/** The whole picture, centred, with the largest square frame in its middle. */
export function initialCrop(source: SourceSize): CropState {
  const scale = displayScale(source, 1);
  const width = source.width * scale;
  const height = source.height * scale;
  const imageX = (CROP_STAGE - width) / 2;
  const imageY = (CROP_STAGE - height) / 2;
  const frameSize = Math.min(width, height);
  return {
    zoom: 1,
    imageX,
    imageY,
    frameX: imageX + (width - frameSize) / 2,
    frameY: imageY + (height - frameSize) / 2,
    frameSize,
  };
}

/** Slides the picture under the frame. */
export function moveImage(source: SourceSize, state: CropState, dx: number, dy: number): CropState {
  const { width, height } = displayed(source, state);
  return {
    ...state,
    imageX: clamp(state.imageX + dx, state.frameX + state.frameSize - width, state.frameX),
    imageY: clamp(state.imageY + dy, state.frameY + state.frameSize - height, state.frameY),
  };
}

/** Moves the frame over the picture. */
export function moveFrame(source: SourceSize, state: CropState, dx: number, dy: number): CropState {
  const bounds = frameBounds(source, state);
  return {
    ...state,
    frameX: clamp(state.frameX + dx, bounds.left, bounds.right - state.frameSize),
    frameY: clamp(state.frameY + dy, bounds.top, bounds.bottom - state.frameSize),
  };
}

/** Drags one corner; the opposite corner stays where it is. */
export function resizeFrameFromCorner(
  source: SourceSize,
  state: CropState,
  corner: CropCorner,
  dx: number,
  dy: number,
): CropState {
  const bounds = frameBounds(source, state);
  const east = corner === 'ne' || corner === 'se';
  const south = corner === 'sw' || corner === 'se';
  const anchorX = east ? state.frameX : state.frameX + state.frameSize;
  const anchorY = south ? state.frameY : state.frameY + state.frameSize;
  const growth = ((east ? dx : -dx) + (south ? dy : -dy)) / 2;
  const room = Math.min(
    east ? bounds.right - anchorX : anchorX - bounds.left,
    south ? bounds.bottom - anchorY : anchorY - bounds.top,
  );
  const frameSize = clamp(state.frameSize + growth, Math.min(MIN_FRAME, room), room);
  return {
    ...state,
    frameSize,
    frameX: east ? anchorX : anchorX - frameSize,
    frameY: south ? anchorY : anchorY - frameSize,
  };
}

/** Largest frame that fits over the visible picture. */
export function maxFrameSize(source: SourceSize, state: CropState): number {
  const bounds = frameBounds(source, state);
  return Math.min(bounds.right - bounds.left, bounds.bottom - bounds.top);
}

/** Resizes the frame around its centre. */
export function setFrameSize(source: SourceSize, state: CropState, size: number): CropState {
  const bounds = frameBounds(source, state);
  const largest = maxFrameSize(source, state);
  const frameSize = clamp(size, Math.min(MIN_FRAME, largest), largest);
  const centerX = state.frameX + state.frameSize / 2;
  const centerY = state.frameY + state.frameSize / 2;
  return {
    ...state,
    frameSize,
    frameX: clamp(centerX - frameSize / 2, bounds.left, bounds.right - frameSize),
    frameY: clamp(centerY - frameSize / 2, bounds.top, bounds.bottom - frameSize),
  };
}

/**
 * Zooms the picture around the frame's centre. Zooming out far enough that
 * the picture would no longer cover the frame shrinks the frame with it.
 */
export function setZoom(source: SourceSize, state: CropState, zoom: number): CropState {
  const next = clamp(zoom, 1, MAX_ZOOM);
  const before = displayScale(source, state.zoom);
  const after = displayScale(source, next);
  const centerX = state.frameX + state.frameSize / 2;
  const centerY = state.frameY + state.frameSize / 2;
  const width = source.width * after;
  const height = source.height * after;
  const frameSize = Math.min(state.frameSize, width, height);
  const frameX = clamp(centerX - frameSize / 2, 0, CROP_STAGE - frameSize);
  const frameY = clamp(centerY - frameSize / 2, 0, CROP_STAGE - frameSize);
  const imageX = centerX - ((centerX - state.imageX) / before) * after;
  const imageY = centerY - ((centerY - state.imageY) / before) * after;
  return {
    zoom: next,
    frameSize,
    frameX,
    frameY,
    imageX: clamp(imageX, frameX + frameSize - width, frameX),
    imageY: clamp(imageY, frameY + frameSize - height, frameY),
  };
}

/** The square of the original picture, in its own pixels, that the frame covers. */
export function toSourceCrop(source: SourceSize, state: CropState): SourceCrop {
  const scale = displayScale(source, state.zoom);
  const side = clamp(Math.round(state.frameSize / scale), 1, Math.min(source.width, source.height));
  return {
    side,
    x: clamp(Math.round((state.frameX - state.imageX) / scale), 0, source.width - side),
    y: clamp(Math.round((state.frameY - state.imageY) / scale), 0, source.height - side),
  };
}

/** Slider position (0–100) ↔ zoom, so each step feels the same size. */
export const zoomToSlider = (zoom: number) => (Math.log(zoom) / Math.log(MAX_ZOOM)) * 100;
export const sliderToZoom = (value: number) => MAX_ZOOM ** (clamp(value, 0, 100) / 100);
