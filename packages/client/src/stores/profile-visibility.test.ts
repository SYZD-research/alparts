import { describe, expect, it } from 'vitest';
import type { WorkspaceMember } from '@alparts/shared';
import { isPictureHidden } from './profile-visibility';

const member = (userId: string, profileFlagged: boolean) => ({ userId, profileFlagged } as WorkspaceMember);

describe('picture visibility in a workspace', () => {
  const members = [member('shown', false), member('warned', true)];

  it('follows the mark on current members', () => {
    expect(isPictureHidden('shown', members, null)).toBe(false);
    expect(isPictureHidden('warned', members, { ids: new Set(), complete: true })).toBe(true);
  });

  it('keeps a warned former member hidden next to their old messages', () => {
    expect(isPictureHidden('left', members, { ids: new Set(['left']), complete: true })).toBe(true);
    expect(isPictureHidden('other', members, { ids: new Set(['left']), complete: true })).toBe(false);
  });

  it('hides former members while the warned list is unknown or incomplete', () => {
    expect(isPictureHidden('left', members, null)).toBe(true);
    expect(isPictureHidden('other', members, { ids: new Set(), complete: false })).toBe(true);
  });
});
