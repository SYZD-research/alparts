import { describe, expect, it } from 'vitest';
import { clampPaneWidth } from './ResizablePane';

describe('resizable pane bounds', () => {
  it('clamps and rounds pointer-derived widths', () => {
    expect(clampPaneWidth(240.4, 176, 420)).toBe(240);
    expect(clampPaneWidth(10, 176, 420)).toBe(176);
    expect(clampPaneWidth(900, 176, 420)).toBe(420);
    expect(clampPaneWidth(Number.NaN, 176, 420)).toBe(176);
  });
});
