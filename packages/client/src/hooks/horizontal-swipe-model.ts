export type SwipeDirection = 'left' | 'right' | 'both';

interface SwipePoint {
  pointerId: number;
  clientX: number;
  clientY: number;
}

interface SwipeSession {
  pointerId: number;
  startX: number;
  startY: number;
  offsetX: number;
  isDragging: boolean;
  rejected: boolean;
}

/** Tracks intent separately from action thresholds so nested surfaces can share a touch. */
export class HorizontalSwipeGesture {
  private session: SwipeSession | null = null;

  constructor(private readonly direction: SwipeDirection) {}

  get pointerId(): number | undefined {
    return this.session?.pointerId;
  }

  get offsetX(): number {
    return this.session?.offsetX || 0;
  }

  get isDragging(): boolean {
    return this.session?.isDragging || false;
  }

  start(point: SwipePoint): void {
    this.session = {
      pointerId: point.pointerId,
      startX: point.clientX,
      startY: point.clientY,
      offsetX: 0,
      isDragging: false,
      rejected: false,
    };
  }

  move(point: SwipePoint): void {
    const session = this.session;
    if (!session || session.pointerId !== point.pointerId || session.rejected) return;
    const distanceX = point.clientX - session.startX;
    const distanceY = point.clientY - session.startY;
    const horizontal = Math.abs(distanceX);
    const vertical = Math.abs(distanceY);

    if (!session.isDragging) {
      if (Math.max(horizontal, vertical) < 10) return;
      if (vertical >= horizontal) {
        session.rejected = true;
        return;
      }
      if (horizontal < vertical * 1.25) return;
      if ((this.direction === 'left' && distanceX > 0) || (this.direction === 'right' && distanceX < 0)) {
        session.rejected = true;
        return;
      }
      session.isDragging = true;
    }

    session.offsetX = this.direction === 'left'
      ? Math.min(0, distanceX)
      : this.direction === 'right'
        ? Math.max(0, distanceX)
        : distanceX;
  }

  end(point: SwipePoint): { distanceX: number; dragged: boolean } | null {
    if (!this.session || this.session.pointerId !== point.pointerId) return null;
    // Release alone must not lock a gesture that never received a horizontal move.
    if (this.isDragging) this.move(point);
    const result = { distanceX: this.offsetX, dragged: this.isDragging };
    this.cancel();
    return result;
  }

  cancel(): void {
    this.session = null;
  }
}
