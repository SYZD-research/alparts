import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

// Never a real database: the room grant fails closed and is only logged.
process.env.DATABASE_URL = 'postgres://test:test@127.0.0.1:1/alparts_test';
process.env.S3_ACCESS_KEY ||= 'test-access-key';
process.env.S3_SECRET_KEY ||= 'test-secret-key';
process.env.AUDIT_INTEGRITY_KEY ||= 'test-audit-integrity-key-at-least-32-bytes';
process.env.PASSWORD_PEPPER ||= 'test-only-password-pepper-at-least-32-bytes';

function fakeIo() {
  const emitted: Array<{ rooms: string | string[]; event: string; payload: unknown }> = [];
  return {
    emitted,
    to(rooms: string | string[]) {
      return {
        emit(event: string, payload: unknown) {
          emitted.push({ rooms, event, payload });
          return true;
        },
      };
    },
    in() {
      return { socketsJoin() {} };
    },
  };
}

describe('workspace announcements', () => {
  it('tells a workspace that its channels changed without naming one', async () => {
    const { emitWorkspaceChannelsChanged } = await import('./workspace-events.js');
    const io = fakeIo();

    emitWorkspaceChannelsChanged(io as never, 'w1');

    assert.deepEqual(io.emitted, [
      { rooms: 'workspace:w1', event: 'workspace:channels-changed', payload: { workspaceId: 'w1' } },
    ]);
  });

  it('tells a workspace who joined it, also when the joiner has no connection yet', async () => {
    const { announceWorkspaceJoin } = await import('./workspace-events.js');
    const io = fakeIo();

    await announceWorkspaceJoin(io as never, 'u1', 'w1');

    assert.deepEqual(io.emitted.filter((entry) => entry.event === 'workspace:member-added'), [
      { rooms: 'workspace:w1', event: 'workspace:member-added', payload: { workspaceId: 'w1', userId: 'u1' } },
    ]);
  });

  it('does nothing without a socket server', async () => {
    const { announceWorkspaceJoin, emitWorkspaceChannelsChanged } = await import('./workspace-events.js');
    emitWorkspaceChannelsChanged(undefined, 'w1');
    await announceWorkspaceJoin(undefined, 'u1', 'w1');
  });
});
