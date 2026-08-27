import { describe, expect, it } from 'vitest';
import { hasCombinedPermission } from './permission-model';

describe('hasCombinedPermission', () => {
  it('combines role permissions and fails closed for malformed values', () => {
    expect(hasCombinedPermission(['64', '128'], 192)).toBe(true);
    expect(hasCombinedPermission(['invalid', '64'], 128)).toBe(false);
  });
});
