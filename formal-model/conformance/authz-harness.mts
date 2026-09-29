// Evaluates authorization cases with the real server implementation.
// Input: JSON array of cases. Output: permission metadata and one result per case.
// Never touches a database: only snapshot-based pure functions are called.
import { readFileSync } from 'node:fs';

process.env.NODE_ENV = 'test';
process.env.DATABASE_URL ||= 'postgres://test:test@127.0.0.1:5432/alparts_test';
process.env.MINIO_ACCESS_KEY ||= 'test-access-key';
process.env.MINIO_SECRET_KEY ||= 'test-secret-key';
process.env.JWT_SECRET ||= 'formal-model-conformance-jwt-secret-32-bytes';
process.env.PASSWORD_PEPPER ||= 'formal-model-conformance-pepper-32-bytes';
process.env.AUDIT_INTEGRITY_KEY ||= 'formal-model-conformance-audit-key-32-bytes';

const service = await import('../../packages/server/src/services/authorization.service.ts');
const { Permissions } = await import('../../packages/shared/src/constants/index.ts');

interface Case {
  owner: string;
  roles: Record<string, { permissions: number; position: number }>;
  members: Record<string, string[]>;
  channels: Record<string, { category: string | null; private: boolean; voice: boolean }>;
  categoryOverrides: Array<[string, string, number, number]>;
  channelOverrides: Array<[string, string, number, number]>;
  privateMembers: Record<string, string[]>;
  guard?: { actor: string; after: Case };
}

function snapshotOf(input: Case) {
  const workspaceId = 'ws';
  const channels = Object.entries(input.channels).map(([id, ch]) => ({
    id, workspaceId, categoryId: ch.category, isPrivate: ch.private, type: ch.voice ? 'voice' : 'text',
  }));
  const group = (rows: Array<[string, string, number, number]>) => {
    const result = new Map<string, Array<{ roleId: string; allowMask: number; denyMask: number }>>();
    for (const [target, roleId, allowMask, denyMask] of rows) {
      result.set(target, [...(result.get(target) ?? []), { roleId, allowMask, denyMask }]);
    }
    return result;
  };
  return {
    workspaceId,
    ownerId: input.owner,
    channels,
    channelsById: new Map(channels.map((ch) => [ch.id, ch])),
    membersByUserId: new Map(Object.keys(input.members).map((userId) => [userId, { id: `m-${userId}`, userId }])),
    rolesById: new Map(Object.entries(input.roles).map(([id, role]) => [id, { id, name: id, ...role }])),
    roleIdsByUserId: new Map(Object.entries(input.members)),
    categoryOverridesById: group(input.categoryOverrides),
    channelOverridesById: group(input.channelOverrides),
    privateMemberIdsByChannelId: new Map(Object.entries(input.privateMembers).map(([ch, users]) => [ch, new Set(users)])),
  };
}

const cases = JSON.parse(readFileSync(0, 'utf8')) as Case[];
const output = cases.map((input) => {
  const snapshot = snapshotOf(input);
  if (input.guard) {
    try {
      service.assertNoSuperiorAccessLoss(snapshot as any, snapshotOf(input.guard.after) as any, input.guard.actor);
      return { allowed: true };
    } catch (error) {
      if (!(error instanceof Error) || error.message !== 'MEMBER_HIERARCHY') throw error;
      return { allowed: false };
    }
  }
  const masks: Record<string, Record<string, number>> = {};
  for (const userId of [...Object.keys(input.members), '__nonmember__']) {
    masks[userId] = {};
    for (const channel of snapshot.channels) {
      const authorization = service.getChannelAuthorizationFromSnapshot(snapshot as any, userId, channel, {}, false);
      masks[userId][channel.id] = authorization ? authorization.permissions : -1;
    }
    masks[userId].__missing_channel__ = service.getChannelAuthorizationFromSnapshot(snapshot as any, userId, '__missing_channel__', {}, false)?.permissions ?? -1;
  }
  const viewers = Object.fromEntries(service.captureChannelViewersFromSnapshot(snapshot as any));
  return { masks, viewers };
});
process.stdout.write(JSON.stringify({ permissions: Permissions, channelScopedMask: service.CHANNEL_SCOPED_PERMISSION_MASK, results: output }));
