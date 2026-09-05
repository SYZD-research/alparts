import { describe, expect, it } from 'vitest';
import { HorizontalSwipeGesture } from './horizontal-swipe-model';

const point = (clientX: number, clientY = 0, pointerId = 1) => ({ clientX, clientY, pointerId });

describe('horizontal touch intent', () => {
  it('waits for a deliberate horizontal move and only returns an action on release', () => {
    const gesture = new HorizontalSwipeGesture('left');
    gesture.start(point(200));
    gesture.move(point(193, 2));
    expect(gesture.isDragging).toBe(false);
    expect(gesture.offsetX).toBe(0);
    gesture.move(point(120, 6));
    expect(gesture.isDragging).toBe(true);
    expect(gesture.offsetX).toBe(-80);
    expect(gesture.end(point(110, 6))).toEqual({ distanceX: -90, dragged: true });
    expect(gesture.end(point(110, 6))).toBeNull();
    expect(gesture.offsetX).toBe(0);
  });

  it('keeps a vertical scroll rejected even if it later moves sideways', () => {
    const gesture = new HorizontalSwipeGesture('left');
    gesture.start(point(200));
    gesture.move(point(197, 20));
    gesture.move(point(20, 25));
    expect(gesture.end(point(20, 25))).toEqual({ distanceX: 0, dragged: false });
  });

  it('waits for horizontal dominance on diagonal movement', () => {
    const gesture = new HorizontalSwipeGesture('left');
    gesture.start(point(200));
    gesture.move(point(180, 19));
    expect(gesture.isDragging).toBe(false);
    gesture.move(point(160, 20));
    expect(gesture.isDragging).toBe(true);
  });

  it('lets nested surfaces claim their own directions without both dragging', () => {
    const message = new HorizontalSwipeGesture('left');
    const navigation = new HorizontalSwipeGesture('right');
    for (const gesture of [message, navigation]) {
      gesture.start(point(100));
      gesture.move(point(180, 2));
    }
    expect(message.isDragging).toBe(false);
    expect(navigation.isDragging).toBe(true);
    expect(message.end(point(180, 2))).toEqual({ distanceX: 0, dragged: false });
    expect(navigation.end(point(180, 2))).toEqual({ distanceX: 80, dragged: true });
  });

  it('uses the final distance so returning below an action threshold cancels that action', () => {
    const gesture = new HorizontalSwipeGesture('left');
    gesture.start(point(200));
    gesture.move(point(20));
    gesture.move(point(170));
    expect(gesture.end(point(195))).toEqual({ distanceX: -5, dragged: true });
  });

  it('clamps a reversal past the starting point and never changes the claimed direction', () => {
    const gesture = new HorizontalSwipeGesture('left');
    gesture.start(point(200));
    gesture.move(point(20));
    expect(gesture.end(point(250))).toEqual({ distanceX: 0, dragged: true });
  });

  it('ignores another pointer and clears all movement on cancellation', () => {
    const gesture = new HorizontalSwipeGesture('left');
    gesture.start(point(200));
    gesture.move(point(20, 0, 2));
    expect(gesture.isDragging).toBe(false);
    gesture.move(point(20));
    expect(gesture.end(point(20, 0, 2))).toBeNull();
    gesture.cancel();
    expect(gesture.end(point(20))).toBeNull();
    expect(gesture.isDragging).toBe(false);
    expect(gesture.offsetX).toBe(0);
  });

  it('does not infer a swipe from a release without a horizontal move', () => {
    const gesture = new HorizontalSwipeGesture('both');
    gesture.start(point(200));
    expect(gesture.end(point(20))).toEqual({ distanceX: 0, dragged: false });
  });
});
