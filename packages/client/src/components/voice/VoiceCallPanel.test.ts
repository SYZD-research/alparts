import { describe, expect, it, vi } from 'vitest';
import { releaseOnWindowBlur } from './VoiceCallPanel';

describe('push-to-talk release on focus loss', () => {
  it('releases on blur and stops listening once cleaned up', () => {
    const target = new EventTarget();
    const release = vi.fn();
    const stop = releaseOnWindowBlur(target, release);

    target.dispatchEvent(new Event('blur'));
    expect(release).toHaveBeenCalledTimes(1);

    stop();
    target.dispatchEvent(new Event('blur'));
    expect(release).toHaveBeenCalledTimes(1);
  });
});
