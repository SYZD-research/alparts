import { describe, expect, it } from 'vitest';
import { padMessage, unpadMessage } from './message-padding';

describe('authenticated message length buckets', () => {
  it('round trips whitespace, empty attachments, Unicode and the maximum message', () => {
    for (const text of ['', '  hello\n ', '日本語🙂', '界'.repeat(4000)]) {
      const padded = padMessage(text);
      expect(padded.length & (padded.length - 1)).toBe(0);
      expect(unpadMessage(padded)).toBe(text);
    }
    expect(padMessage('one').length).toBe(padMessage('a'.repeat(900)).length);
    expect(unpadMessage(new TextEncoder().encode('legacy text  '))).toBe('legacy text  ');
  });
  it('rejects invalid lengths, versions, padding and oversized content', () => {
    const padded = padMessage('one');
    padded[padded.length - 1] = 1;
    expect(() => unpadMessage(padded)).toThrow();
    const badLength = padMessage('one');
    new DataView(badLength.buffer).setUint32(8, 0xffffffff);
    expect(() => unpadMessage(badLength)).toThrow();
    const badVersion = padMessage('one');
    badVersion[7] = 2;
    expect(() => unpadMessage(badVersion)).toThrow();
    expect(() => padMessage('a'.repeat(4001))).toThrow();
  });
});
