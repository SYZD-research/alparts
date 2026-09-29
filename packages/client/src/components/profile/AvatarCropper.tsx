import { useEffect, useMemo, useRef, useState, type KeyboardEvent, type PointerEvent } from 'react';
import {
  CROP_STAGE,
  displayScale,
  initialCrop,
  maxFrameSize,
  MIN_FRAME,
  moveFrame,
  moveImage,
  resizeFrameFromCorner,
  setFrameSize,
  setZoom,
  sliderToZoom,
  toSourceCrop,
  zoomToSlider,
  type CropCorner,
  type CropState,
  type SourceCrop,
} from './avatar-crop-model';

const PREVIEW_SIZE = 72;
const CORNERS: { corner: CropCorner; className: string }[] = [
  { corner: 'nw', className: '-left-2 -top-2 cursor-nwse-resize' },
  { corner: 'ne', className: '-right-2 -top-2 cursor-nesw-resize' },
  { corner: 'sw', className: '-bottom-2 -left-2 cursor-nesw-resize' },
  { corner: 'se', className: '-bottom-2 -right-2 cursor-nwse-resize' },
];

type Drag = { mode: 'image' | 'frame' | CropCorner; x: number; y: number; start: CropState };

/** Choose which part of a picture becomes the avatar: drag, zoom and resize the frame. */
export function AvatarCropper({ bitmap, busy, onConfirm, onCancel }: {
  bitmap: ImageBitmap;
  busy: boolean;
  onConfirm: (crop: SourceCrop) => void;
  onCancel: () => void;
}) {
  const source = useMemo(() => ({ width: bitmap.width, height: bitmap.height }), [bitmap]);
  const [state, setState] = useState(() => initialCrop(source));
  const drag = useRef<Drag | null>(null);
  const stage = useRef<HTMLDivElement>(null);
  const canvas = useRef<HTMLCanvasElement>(null);
  const preview = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const element = canvas.current;
    const context = element?.getContext('2d');
    if (!element || !context) return;
    const ratio = window.devicePixelRatio || 1;
    element.width = CROP_STAGE * ratio;
    element.height = CROP_STAGE * ratio;
    const scale = displayScale(source, state.zoom);
    context.setTransform(ratio, 0, 0, ratio, 0, 0);
    context.clearRect(0, 0, CROP_STAGE, CROP_STAGE);
    context.imageSmoothingQuality = 'high';
    context.drawImage(bitmap, state.imageX, state.imageY, source.width * scale, source.height * scale);

    const small = preview.current?.getContext('2d');
    if (!preview.current || !small) return;
    preview.current.width = PREVIEW_SIZE * ratio;
    preview.current.height = PREVIEW_SIZE * ratio;
    const crop = toSourceCrop(source, state);
    small.imageSmoothingQuality = 'high';
    small.drawImage(bitmap, crop.x, crop.y, crop.side, crop.side, 0, 0, preview.current.width, preview.current.height);
  }, [bitmap, source, state]);

  // Wheel zoom must be able to stop the dialog from scrolling.
  useEffect(() => {
    const element = stage.current;
    if (!element) return;
    const onWheel = (event: WheelEvent) => {
      event.preventDefault();
      setState((current) => setZoom(source, current, current.zoom * Math.exp(-event.deltaY * 0.0015)));
    };
    element.addEventListener('wheel', onWheel, { passive: false });
    return () => element.removeEventListener('wheel', onWheel);
  }, [source]);

  const pointerDown = (event: PointerEvent<HTMLDivElement>) => {
    if (busy || event.button !== 0) return;
    const target = event.target as HTMLElement;
    const corner = target.closest<HTMLElement>('[data-corner]')?.dataset.corner as CropCorner | undefined;
    const mode = corner ?? (target.closest('[data-frame]') ? 'frame' : 'image');
    drag.current = { mode, x: event.clientX, y: event.clientY, start: state };
    event.currentTarget.setPointerCapture(event.pointerId);
    event.preventDefault();
  };

  const pointerMove = (event: PointerEvent<HTMLDivElement>) => {
    const active = drag.current;
    if (!active) return;
    const dx = event.clientX - active.x;
    const dy = event.clientY - active.y;
    if (active.mode === 'image') setState(moveImage(source, active.start, dx, dy));
    else if (active.mode === 'frame') setState(moveFrame(source, active.start, dx, dy));
    else setState(resizeFrameFromCorner(source, active.start, active.mode, dx, dy));
  };

  const pointerUp = () => { drag.current = null; };

  const keyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const step = event.shiftKey ? 16 : 4;
    const moves: Record<string, [number, number]> = {
      ArrowLeft: [step, 0], ArrowRight: [-step, 0], ArrowUp: [0, step], ArrowDown: [0, -step],
    };
    if (moves[event.key]) setState(moveImage(source, state, ...moves[event.key]));
    else if (event.key === '+' || event.key === '=') setState(setZoom(source, state, state.zoom * 1.1));
    else if (event.key === '-') setState(setZoom(source, state, state.zoom / 1.1));
    else return;
    event.preventDefault();
  };

  const largest = maxFrameSize(source, state);
  const zoomBy = (factor: number) => setState(setZoom(source, state, state.zoom * factor));
  const control = 'h-8 w-8 shrink-0 rounded bg-discord-hover text-white disabled:opacity-50';

  return (
    <div className="space-y-4">
      <p className="text-sm text-discord-muted">
        枠の中がアイコンになります。画像や枠をドラッグして位置を、枠の角で大きさを調整できます。
      </p>
      <div className="flex flex-wrap items-start justify-center gap-4">
        <div
          ref={stage}
          role="group"
          aria-label="アイコンにする範囲"
          tabIndex={0}
          onPointerDown={pointerDown}
          onPointerMove={pointerMove}
          onPointerUp={pointerUp}
          onPointerCancel={pointerUp}
          onKeyDown={keyDown}
          className="relative shrink-0 cursor-move touch-none select-none overflow-hidden rounded bg-black/40 outline-none focus-visible:ring-2 focus-visible:ring-discord-accent"
          style={{ width: CROP_STAGE, height: CROP_STAGE }}
        >
          <canvas ref={canvas} className="pointer-events-none absolute inset-0" style={{ width: CROP_STAGE, height: CROP_STAGE }} />
          <div
            data-frame
            className="absolute border-2 border-white shadow-[0_0_0_9999px_rgba(0,0,0,0.55)]"
            style={{ left: state.frameX, top: state.frameY, width: state.frameSize, height: state.frameSize }}
          >
            <div className="pointer-events-none absolute inset-0 rounded-full border border-white/70" />
            {CORNERS.map(({ corner, className }) => (
              <span key={corner} data-corner={corner} className={`absolute h-4 w-4 rounded-sm border-2 border-discord-bg bg-white ${className}`} />
            ))}
          </div>
        </div>
        <div className="flex flex-col items-center gap-1 text-xs text-discord-muted">
          <canvas ref={preview} className="rounded-full bg-black/40" style={{ width: PREVIEW_SIZE, height: PREVIEW_SIZE }} />
          仕上がり
        </div>
      </div>

      <div className="space-y-3 text-sm text-discord-muted">
        <div className="flex items-center gap-2">
          <span className="w-20 shrink-0">拡大</span>
          <button type="button" aria-label="縮小" disabled={busy} onClick={() => zoomBy(1 / 1.25)} className={control}>−</button>
          <input
            type="range"
            min={0}
            max={100}
            step={1}
            disabled={busy}
            aria-label="拡大率"
            value={Math.round(zoomToSlider(state.zoom))}
            onChange={(event) => setState(setZoom(source, state, sliderToZoom(Number(event.target.value))))}
            className="min-w-0 flex-1 accent-discord-accent"
          />
          <button type="button" aria-label="拡大" disabled={busy} onClick={() => zoomBy(1.25)} className={control}>＋</button>
        </div>
        <label className="flex items-center gap-2">
          <span className="w-20 shrink-0">枠の大きさ</span>
          <input
            type="range"
            min={Math.min(MIN_FRAME, largest)}
            max={largest}
            step={1}
            disabled={busy || largest <= MIN_FRAME}
            value={Math.round(state.frameSize)}
            onChange={(event) => setState(setFrameSize(source, state, Number(event.target.value)))}
            className="min-w-0 flex-1 accent-discord-accent"
          />
        </label>
      </div>

      <div className="flex justify-between gap-2">
        <button type="button" disabled={busy} onClick={() => setState(initialCrop(source))} className="rounded px-3 py-2 text-sm text-discord-muted hover:bg-discord-hover disabled:opacity-50">
          元に戻す
        </button>
        <div className="flex gap-2">
          <button type="button" disabled={busy} onClick={onCancel} className="rounded px-3 py-2 text-sm text-discord-muted hover:bg-discord-hover disabled:opacity-50">
            やめる
          </button>
          <button type="button" disabled={busy} onClick={() => onConfirm(toSourceCrop(source, state))} className="rounded bg-discord-accent px-4 py-2 text-sm font-medium text-white disabled:opacity-50">
            {busy ? '保存中…' : 'この範囲で設定'}
          </button>
        </div>
      </div>
    </div>
  );
}
