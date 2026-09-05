import { useEffect, useMemo, useRef, useState, type MouseEvent, type PointerEvent } from 'react';
import { HorizontalSwipeGesture, type SwipeDirection } from './horizontal-swipe-model';

interface Options {
  enabled: boolean;
  direction: SwipeDirection;
  onSwipe: (distanceX: number) => void;
}

const INTERACTIVE_TARGETS = [
  'a', 'button', 'input', 'textarea', 'select', 'label', 'summary',
  'audio', 'video', 'iframe', 'pre', 'code',
  '[contenteditable]:not([contenteditable="false"])',
  '[role="button"]', '[role="slider"]', '[role="textbox"]', '[role="dialog"]',
  '[data-no-swipe]',
].join(',');

/** Touch-only; callers apply touch-action: pan-y pinch-zoom to their surface. */
export function useHorizontalSwipe({ enabled, direction, onSwipe }: Options) {
  const gesture = useMemo(() => new HorizontalSwipeGesture(direction), [direction]);
  const [offsetX, setOffsetX] = useState(0);
  const [isDragging, setIsDragging] = useState(false);
  const detachListeners = useRef<(() => void) | null>(null);
  const captureElement = useRef<HTMLElement | null>(null);
  const suppressClickUntil = useRef(0);

  const releaseCapture = () => {
    const element = captureElement.current;
    const pointerId = gesture.pointerId;
    captureElement.current = null;
    if (element && pointerId !== undefined && element.hasPointerCapture?.(pointerId)) {
      element.releasePointerCapture(pointerId);
    }
  };

  const cancel = () => {
    if (gesture.isDragging) suppressClickUntil.current = Date.now() + 500;
    releaseCapture();
    gesture.cancel();
    detachListeners.current?.();
    detachListeners.current = null;
    setOffsetX(0);
    setIsDragging(false);
  };

  useEffect(() => {
    cancel();
    return () => {
      releaseCapture();
      gesture.cancel();
      detachListeners.current?.();
      detachListeners.current = null;
    };
  }, [enabled, gesture]);

  const handlers = {
    onPointerDown: (event: PointerEvent<HTMLElement>) => {
      if (event.pointerType !== 'touch') return;
      if (!event.isPrimary || gesture.pointerId !== undefined) {
        cancel();
        return;
      }
      suppressClickUntil.current = 0;
      if (!enabled || event.defaultPrevented || (event.target instanceof Element && event.target.closest(INTERACTIVE_TARGETS))) return;
      gesture.start(event);

      const ownerDocument = event.currentTarget.ownerDocument;
      const cancelOtherTouch = (next: globalThis.PointerEvent) => {
        if (next.pointerType === 'touch' && next.pointerId !== gesture.pointerId) cancel();
      };
      const cancelUnfinished = (next: globalThis.PointerEvent) => {
        if (next.pointerId === gesture.pointerId) cancel();
      };
      ownerDocument.addEventListener('pointerdown', cancelOtherTouch, true);
      ownerDocument.addEventListener('pointerup', cancelUnfinished);
      ownerDocument.addEventListener('pointercancel', cancelUnfinished);
      detachListeners.current = () => {
        ownerDocument.removeEventListener('pointerdown', cancelOtherTouch, true);
        ownerDocument.removeEventListener('pointerup', cancelUnfinished);
        ownerDocument.removeEventListener('pointercancel', cancelUnfinished);
      };
    },
    onPointerMove: (event: PointerEvent<HTMLElement>) => {
      if (!enabled || event.pointerId !== gesture.pointerId) return;
      gesture.move(event);
      if (!gesture.isDragging) return;
      if (!captureElement.current) {
        try {
          event.currentTarget.setPointerCapture(event.pointerId);
          captureElement.current = event.currentTarget;
        } catch {
          // A browser may already have cancelled capture for native scrolling.
          cancel();
          return;
        }
      }
      event.preventDefault();
      event.stopPropagation();
      setOffsetX(gesture.offsetX);
      setIsDragging(true);
    },
    onPointerUp: (event: PointerEvent<HTMLElement>) => {
      if (event.pointerId !== gesture.pointerId) return;
      releaseCapture();
      const result = gesture.end(event);
      detachListeners.current?.();
      detachListeners.current = null;
      setOffsetX(0);
      setIsDragging(false);
      if (!result?.dragged) return;
      suppressClickUntil.current = Date.now() + 500;
      event.preventDefault();
      event.stopPropagation();
      if (enabled && result.distanceX !== 0) onSwipe(result.distanceX);
    },
    onPointerCancel: (event: PointerEvent<HTMLElement>) => {
      if (event.pointerId === gesture.pointerId) cancel();
    },
    onLostPointerCapture: (event: PointerEvent<HTMLElement>) => {
      // Touch begins with implicit capture on the deepest target. Losing that
      // child's capture while moving it to this surface is expected.
      if (event.target === captureElement.current && event.pointerId === gesture.pointerId) cancel();
    },
    onClickCapture: (event: MouseEvent<HTMLElement>) => {
      if (event.detail !== 0 && Date.now() < suppressClickUntil.current) {
        event.preventDefault();
        event.stopPropagation();
        suppressClickUntil.current = 0;
      }
    },
  };

  return { handlers, offsetX, isDragging };
}
