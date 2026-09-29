import { describe, expect, it } from 'vitest';
import { ApiError } from '../../services/api';
import { AvatarImageError } from '../../services/avatar-image';
import { bioLengthStatus, profileErrorMessage } from './profile-model';

describe('profile model', () => {
  it('counts characters and lines the same way as the server', () => {
    expect(bioLengthStatus('  a\nb  ')).toEqual({ characters: 3, lines: 2, ok: true });
    expect(bioLengthStatus('😀'.repeat(200)).ok).toBe(true);
    expect(bioLengthStatus('😀'.repeat(201)).ok).toBe(false);
    expect(bioLengthStatus('1\n2\n3\n4\n5\n6').ok).toBe(false);
    expect(bioLengthStatus('').lines).toBe(0);
  });

  it('explains failures without technical detail', () => {
    expect(profileErrorMessage(new AvatarImageError('type'))).toContain('PNG');
    expect(profileErrorMessage(new ApiError('x', 409, 'PROFILE_APPEAL_USED'))).toBe('解除の依頼はすでに使用済みです。');
    expect(profileErrorMessage(new Error('boom'))).toBe('保存できませんでした。もう一度お試しください。');
  });
});
