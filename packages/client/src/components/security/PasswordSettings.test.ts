import { describe, expect, it } from 'vitest';
import { newPasswordProblem } from './PasswordSettings';

describe('new password checks', () => {
  it('asks for a long enough password typed the same way twice', () => {
    expect(newPasswordProblem('short', 'short')).toMatch(/12文字以上/);
    expect(newPasswordProblem('a'.repeat(73), 'a'.repeat(73))).toMatch(/長すぎます/);
    expect(newPasswordProblem('あ'.repeat(25), 'あ'.repeat(25))).toMatch(/長すぎます/);
    const typed = 'twelve-chars-or-more';
    expect(newPasswordProblem(typed, `${typed}?`)).toMatch(/一致しません/);
    expect(newPasswordProblem(typed, typed)).toBeNull();
  });
});
