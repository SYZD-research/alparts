import { describe, expect, it } from 'vitest';
import {
  CROP_STAGE,
  displayScale,
  initialCrop,
  MAX_ZOOM,
  MIN_FRAME,
  moveFrame,
  moveImage,
  resizeFrameFromCorner,
  setFrameSize,
  setZoom,
  sliderToZoom,
  toSourceCrop,
  zoomToSlider,
  type CropState,
  type SourceSize,
} from './avatar-crop-model';

const wide: SourceSize = { width: 1200, height: 600 };
const tall: SourceSize = { width: 300, height: 900 };

/** The rules every state must keep: frame inside the editor, picture covering the frame. */
function expectValid(source: SourceSize, state: CropState) {
  const scale = displayScale(source, state.zoom);
  const epsilon = 1e-6;
  expect(state.frameX).toBeGreaterThanOrEqual(-epsilon);
  expect(state.frameY).toBeGreaterThanOrEqual(-epsilon);
  expect(state.frameX + state.frameSize).toBeLessThanOrEqual(CROP_STAGE + epsilon);
  expect(state.frameY + state.frameSize).toBeLessThanOrEqual(CROP_STAGE + epsilon);
  expect(state.imageX).toBeLessThanOrEqual(state.frameX + epsilon);
  expect(state.imageY).toBeLessThanOrEqual(state.frameY + epsilon);
  expect(state.imageX + source.width * scale).toBeGreaterThanOrEqual(state.frameX + state.frameSize - epsilon);
  expect(state.imageY + source.height * scale).toBeGreaterThanOrEqual(state.frameY + state.frameSize - epsilon);
  expect(state.zoom).toBeGreaterThanOrEqual(1);
  expect(state.zoom).toBeLessThanOrEqual(MAX_ZOOM);
}

describe('avatar crop', () => {
  it('starts with the largest centred square of the whole picture', () => {
    expect(toSourceCrop(wide, initialCrop(wide))).toEqual({ x: 300, y: 0, side: 600 });
    expect(toSourceCrop(tall, initialCrop(tall))).toEqual({ x: 0, y: 300, side: 300 });
  });

  it('zooming in keeps the frame centre on the same spot and picks a smaller area', () => {
    const start = initialCrop(wide);
    const zoomed = setZoom(wide, start, 2);
    expectValid(wide, zoomed);
    expect(toSourceCrop(wide, zoomed)).toEqual({ x: 450, y: 150, side: 300 });
    expect(setZoom(wide, start, 100).zoom).toBe(MAX_ZOOM);
    expect(setZoom(wide, start, 0.1).zoom).toBe(1);
  });

  it('zooming back out shrinks a frame the picture can no longer cover', () => {
    const big = setFrameSize(wide, setZoom(wide, initialCrop(wide), 3), CROP_STAGE);
    expect(big.frameSize).toBe(CROP_STAGE);
    const out = setZoom(wide, big, 1);
    expectValid(wide, out);
    expect(out.frameSize).toBeCloseTo(CROP_STAGE / 2);
  });

  it('never lets the picture leave part of the frame empty', () => {
    const zoomed = setZoom(wide, initialCrop(wide), 2);
    for (const [dx, dy] of [[5000, 0], [-5000, 0], [0, 5000], [0, -5000], [37, -12]]) {
      const moved = moveImage(wide, zoomed, dx, dy);
      expectValid(wide, moved);
    }
    const crop = toSourceCrop(wide, moveImage(wide, zoomed, 5000, 5000));
    expect(crop.x).toBe(0);
    expect(crop.y).toBe(0);
  });

  it('moves the frame only over the visible picture', () => {
    const small = setFrameSize(wide, initialCrop(wide), 80);
    const corner = moveFrame(wide, small, -5000, -5000);
    expectValid(wide, corner);
    expect(toSourceCrop(wide, corner)).toMatchObject({ x: 0, y: 0 });
    const other = moveFrame(wide, small, 5000, 5000);
    expectValid(wide, other);
    const crop = toSourceCrop(wide, other);
    expect(crop.x + crop.side).toBe(wide.width);
    expect(crop.y + crop.side).toBe(wide.height);
  });

  it('resizes from a corner while the opposite corner stays put', () => {
    const start = initialCrop(wide);
    const shrunk = resizeFrameFromCorner(wide, start, 'se', -60, -40);
    expectValid(wide, shrunk);
    expect(shrunk.frameSize).toBeCloseTo(start.frameSize - 50);
    expect(shrunk.frameX).toBe(start.frameX);
    expect(shrunk.frameY).toBe(start.frameY);

    const fromNw = resizeFrameFromCorner(wide, shrunk, 'nw', 1000, 1000);
    expectValid(wide, fromNw);
    expect(fromNw.frameSize).toBe(MIN_FRAME);
    expect(fromNw.frameX + fromNw.frameSize).toBeCloseTo(shrunk.frameX + shrunk.frameSize);

    const grown = resizeFrameFromCorner(wide, fromNw, 'ne', 5000, -5000);
    expectValid(wide, grown);
    expect(grown.frameX).toBeCloseTo(fromNw.frameX);
    expect(grown.frameY + grown.frameSize).toBeCloseTo(fromNw.frameY + fromNw.frameSize);
  });

  it('keeps every operation valid on a long sequence of edits', () => {
    let state = initialCrop(tall);
    const steps: ((current: CropState) => CropState)[] = [
      (s) => setZoom(tall, s, 3.7),
      (s) => moveImage(tall, s, -120, 80),
      (s) => resizeFrameFromCorner(tall, s, 'sw', -300, 300),
      (s) => moveFrame(tall, s, 400, -400),
      (s) => setFrameSize(tall, s, 20),
      (s) => setZoom(tall, s, 1),
      (s) => setFrameSize(tall, s, 9999),
      (s) => setZoom(tall, s, 8),
      (s) => resizeFrameFromCorner(tall, s, 'se', 9999, 9999),
    ];
    for (const step of steps) {
      state = step(state);
      expectValid(tall, state);
      const crop = toSourceCrop(tall, state);
      expect(crop.side).toBeGreaterThanOrEqual(1);
      expect(crop.x + crop.side).toBeLessThanOrEqual(tall.width);
      expect(crop.y + crop.side).toBeLessThanOrEqual(tall.height);
    }
  });

  it('maps the zoom slider evenly between the limits', () => {
    expect(sliderToZoom(0)).toBe(1);
    expect(sliderToZoom(100)).toBe(MAX_ZOOM);
    expect(zoomToSlider(sliderToZoom(37))).toBeCloseTo(37);
  });
});
