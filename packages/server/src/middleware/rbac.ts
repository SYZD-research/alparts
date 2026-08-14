import { Response, NextFunction } from 'express';
import { AuthRequest } from './auth.js';
import { db } from '../db/index.js';
import { workspaceMembers, memberRoles } from '../db/schema.js';
import { eq, and } from 'drizzle-orm';

export function requirePermission(permission: number) {
  return async (req: AuthRequest, res: Response, next: NextFunction) => {
    if (!req.userId) {
      res.status(401).json({ error: 'UNAUTHORIZED', message: 'Authentication required', statusCode: 401 });
      return;
    }

    const workspaceId = req.params.workspaceId || req.params.wid;
    if (!workspaceId) {
      next();
      return;
    }

    const perms = await getUserPermissions(req.userId, workspaceId);
    if ((perms & permission) !== permission) {
      res.status(403).json({ error: 'FORBIDDEN', message: 'Insufficient permissions', statusCode: 403 });
      return;
    }

    next();
  };
}

export async function getUserPermissions(userId: string, workspaceId: string): Promise<number> {
  const member = await db.query.workspaceMembers.findFirst({
    where: and(
      eq(workspaceMembers.workspaceId, workspaceId),
      eq(workspaceMembers.userId, userId),
    ),
  });

  if (!member) return 0;

  const memberRolesList = await db.query.memberRoles.findMany({
    where: eq(memberRoles.memberId, member.id),
    with: { role: true },
  });

  return memberRolesList.reduce(
    (acc: number, mr: any) => acc | (mr.role?.permissions ?? 0),
    0,
  );
}
