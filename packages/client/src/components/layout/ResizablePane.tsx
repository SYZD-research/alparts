import { useEffect, useRef, useState, type ReactNode } from 'react';

interface ResizablePaneProps {
  children: ReactNode;
  storageKey: string;
  defaultWidth: number;
  minWidth: number;
  maxWidth: number;
  resizeEdge: 'left' | 'right';
  label: string;
}

export function clampPaneWidth(value: number, minWidth: number, maxWidth: number): number {
  if (!Number.isFinite(value)) return minWidth;
  return Math.min(maxWidth, Math.max(minWidth, Math.round(value)));
}

export function ResizablePane({
  children,
  storageKey,
  defaultWidth,
  minWidth,
  maxWidth,
  resizeEdge,
  label,
}: ResizablePaneProps) {
  const [width, setWidth] = useState(() => readStoredWidth(storageKey, defaultWidth, minWidth, maxWidth));
  const stopDraggingRef = useRef<(() => void) | null>(null);

  useEffect(() => {
    try {
      localStorage.setItem(storageKey, String(width));
    } catch {
      // Layout preference persistence is best-effort (private mode may deny it).
    }
  }, [storageKey, width]);

  useEffect(() => () => stopDraggingRef.current?.(), []);

  const beginResize = (event: React.PointerEvent<HTMLDivElement>) => {
    if (event.button !== 0) return;
    event.preventDefault();
    stopDraggingRef.current?.();
    const startX = event.clientX;
    const startWidth = width;
    const previousCursor = document.body.style.cursor;
    const previousUserSelect = document.body.style.userSelect;
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';

    const move = (pointerEvent: PointerEvent) => {
      const delta = pointerEvent.clientX - startX;
      const next = resizeEdge === 'right' ? startWidth + delta : startWidth - delta;
      setWidth(clampPaneWidth(next, minWidth, maxWidth));
    };
    const stop = () => {
      window.removeEventListener('pointermove', move);
      window.removeEventListener('pointerup', stop);
      window.removeEventListener('pointercancel', stop);
      document.body.style.cursor = previousCursor;
      document.body.style.userSelect = previousUserSelect;
      if (stopDraggingRef.current === stop) stopDraggingRef.current = null;
    };
    stopDraggingRef.current = stop;
    window.addEventListener('pointermove', move);
    window.addEventListener('pointerup', stop, { once: true });
    window.addEventListener('pointercancel', stop, { once: true });
  };

  const resizeWithKeyboard = (event: React.KeyboardEvent<HTMLDivElement>) => {
    const growKey = resizeEdge === 'right' ? 'ArrowRight' : 'ArrowLeft';
    const shrinkKey = resizeEdge === 'right' ? 'ArrowLeft' : 'ArrowRight';
    if (event.key === growKey) {
      event.preventDefault();
      setWidth((current) => clampPaneWidth(current + 12, minWidth, maxWidth));
    } else if (event.key === shrinkKey) {
      event.preventDefault();
      setWidth((current) => clampPaneWidth(current - 12, minWidth, maxWidth));
    } else if (event.key === 'Home') {
      event.preventDefault();
      setWidth(clampPaneWidth(defaultWidth, minWidth, maxWidth));
    }
  };

  return (
    <div className="relative flex min-w-0 flex-shrink-0" style={{ width }}>
      <div className="min-w-0 flex-1">{children}</div>
      <div
        role="separator"
        aria-orientation="vertical"
        aria-label={label}
        aria-valuemin={minWidth}
        aria-valuemax={maxWidth}
        aria-valuenow={width}
        tabIndex={0}
        onPointerDown={beginResize}
        onKeyDown={resizeWithKeyboard}
        onDoubleClick={() => setWidth(clampPaneWidth(defaultWidth, minWidth, maxWidth))}
        title="ドラッグして幅を変更（ダブルクリックで元に戻す）"
        className={`group absolute inset-y-0 z-30 w-2 cursor-col-resize touch-none outline-none ${resizeEdge === 'right' ? '-right-1' : '-left-1'}`}
      >
        <span className="absolute inset-y-0 left-1/2 w-px -translate-x-1/2 bg-transparent transition-colors group-hover:bg-discord-accent group-focus-visible:bg-discord-accent" />
      </div>
    </div>
  );
}

function readStoredWidth(
  storageKey: string,
  defaultWidth: number,
  minWidth: number,
  maxWidth: number,
): number {
  if (typeof window === 'undefined') return clampPaneWidth(defaultWidth, minWidth, maxWidth);
  try {
    const stored = Number(localStorage.getItem(storageKey));
    if (Number.isFinite(stored) && stored > 0) return clampPaneWidth(stored, minWidth, maxWidth);
  } catch {
    // Fall back to the default when storage access is unavailable.
  }
  return clampPaneWidth(defaultWidth, minWidth, maxWidth);
}
