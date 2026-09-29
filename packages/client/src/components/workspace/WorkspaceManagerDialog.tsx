import { useCallback, useEffect, useMemo, useRef, useState, type KeyboardEvent } from 'react';
import { Permissions } from '@alparts/shared';
import { api, type WorkspaceRole } from '../../services/api';
import { useAuthStore } from '../../stores/auth.store';
import { hasCombinedPermission } from '../../stores/permission-model';
import { useUiStore } from '../../stores/ui.store';
import { useWorkspaceStore } from '../../stores/workspace.store';
import { Dialog } from '../ui/Dialog';
import { EffectivePermissionsPanel } from './EffectivePermissionsPanel';
import { InvitationManager } from './InvitationManager';
import { RoleManager } from './RoleManager';
import { AuditLogPanel } from './AuditLogPanel';
import { ProfileFlagsPanel } from './ProfileFlagsPanel';

type ManagementTab = 'accept' | 'invitations' | 'roles' | 'permissions' | 'profiles' | 'audit';

interface TabDefinition {
  id: ManagementTab;
  label: string;
}

export function WorkspaceManagerDialog() {
  const open = useUiStore((state) => state.isWorkspaceManagerOpen);
  const close = useUiStore((state) => state.closeWorkspaceManager);
  const activeWorkspaceId = useWorkspaceStore((state) => state.activeWorkspaceId);
  const workspaces = useWorkspaceStore((state) => state.workspaces);
  const members = useWorkspaceStore((state) => state.members);
  const loadMembers = useWorkspaceStore((state) => state.loadMembers);
  const loadWorkspaces = useWorkspaceStore((state) => state.loadWorkspaces);
  const setActiveWorkspace = useWorkspaceStore((state) => state.setActiveWorkspace);
  const userId = useAuthStore((state) => state.user?.id);
  const currentMember = members.find((member) => member.userId === userId);
  const rolePermissionValues = currentMember?.roles.map((role) => role.permissions) || [];
  const canManageMembers = hasCombinedPermission(rolePermissionValues, Permissions.MANAGE_MEMBERS);
  const canManageRoles = hasCombinedPermission(rolePermissionValues, Permissions.MANAGE_ROLES);
  const canViewAudit = hasCombinedPermission(rolePermissionValues, Permissions.VIEW_AUDIT_LOG);
  const [activeTab, setActiveTab] = useState<ManagementTab>('accept');
  const [roles, setRoles] = useState<WorkspaceRole[]>([]);
  const [rolesLoading, setRolesLoading] = useState(false);
  const [rolesError, setRolesError] = useState<string | null>(null);
  const roleRequest = useRef(0);

  const tabs = useMemo<TabDefinition[]>(() => [
    { id: 'accept', label: '招待を受諾' },
    ...(canManageMembers ? [{ id: 'invitations' as const, label: '招待を管理' }] : []),
    { id: 'roles', label: 'ロール' },
    { id: 'permissions', label: '権限の理由' },
    ...(canManageMembers ? [{ id: 'profiles' as const, label: 'プロフィールの警告' }] : []),
    ...(canViewAudit ? [{ id: 'audit' as const, label: '操作履歴' }] : []),
  ], [canManageMembers, canViewAudit]);

  const loadRoles = useCallback(async () => {
    if (!activeWorkspaceId) return;
    const request = ++roleRequest.current;
    setRolesLoading(true);
    setRolesError(null);
    try {
      const nextRoles = await api.getRoles(activeWorkspaceId);
      if (request === roleRequest.current) setRoles(nextRoles);
    } catch {
      if (request === roleRequest.current) {
        setRoles([]);
        setRolesError('ロールを読み込めませんでした。もう一度お試しください。');
      }
    } finally {
      if (request === roleRequest.current) setRolesLoading(false);
    }
  }, [activeWorkspaceId]);

  useEffect(() => {
    if (!open || !activeWorkspaceId) return;
    setActiveTab(canManageMembers ? 'invitations' : 'accept');
    void loadRoles();
    return () => { roleRequest.current += 1; };
  }, [activeWorkspaceId, canManageMembers, loadRoles, open]);

  useEffect(() => {
    if (!tabs.some((tab) => tab.id === activeTab)) setActiveTab('accept');
  }, [activeTab, tabs]);

  const refreshMembersAndRoles = useCallback(async () => {
    if (!activeWorkspaceId) return;
    await Promise.all([loadRoles(), loadMembers(activeWorkspaceId)]);
  }, [activeWorkspaceId, loadMembers, loadRoles]);

  const handleInvitationAccepted = useCallback(async (workspaceId: string) => {
    await loadWorkspaces();
    await setActiveWorkspace(workspaceId);
  }, [loadWorkspaces, setActiveWorkspace]);

  const onTabKeyDown = (event: KeyboardEvent<HTMLButtonElement>, index: number) => {
    let nextIndex = index;
    if (event.key === 'ArrowRight') nextIndex = (index + 1) % tabs.length;
    else if (event.key === 'ArrowLeft') nextIndex = (index - 1 + tabs.length) % tabs.length;
    else if (event.key === 'Home') nextIndex = 0;
    else if (event.key === 'End') nextIndex = tabs.length - 1;
    else return;
    event.preventDefault();
    setActiveTab(tabs[nextIndex].id);
    document.getElementById(`workspace-management-tab-${tabs[nextIndex].id}`)?.focus();
  };

  const workspaceName = workspaces.find((workspace) => workspace.id === activeWorkspaceId)?.name;

  return (
    <Dialog
      open={open && Boolean(activeWorkspaceId)}
      onClose={close}
      title={`${workspaceName || 'ワークスペース'}の管理`}
      description="招待、ロール、権限、操作履歴を管理します。"
      size="lg"
    >
      {open && activeWorkspaceId && (
        <div>
          <div role="tablist" aria-label="ワークスペース管理" className="mb-5 flex flex-wrap gap-1 border-b border-discord-hover">
            {tabs.map((tab, index) => (
              <button
                key={tab.id}
                id={`workspace-management-tab-${tab.id}`}
                type="button"
                role="tab"
                aria-selected={activeTab === tab.id}
                aria-controls={`workspace-management-panel-${tab.id}`}
                tabIndex={activeTab === tab.id ? 0 : -1}
                onClick={() => setActiveTab(tab.id)}
                onKeyDown={(event) => onTabKeyDown(event, index)}
                className={`border-b-2 px-3 py-2 text-sm ${activeTab === tab.id ? 'border-discord-accent text-white' : 'border-transparent text-discord-muted hover:text-white'}`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          <div id={`workspace-management-panel-${activeTab}`} role="tabpanel" aria-labelledby={`workspace-management-tab-${activeTab}`}>
            {activeTab === 'accept' && (
              <InvitationManager
                mode="accept"
                workspaceId={activeWorkspaceId}
                roles={roles}
                canChooseRole={false}
                onAccepted={handleInvitationAccepted}
              />
            )}
            {activeTab === 'invitations' && canManageMembers && (
              <InvitationManager
                mode="manage"
                workspaceId={activeWorkspaceId}
                roles={roles}
                canChooseRole={canManageRoles}
                onAccepted={handleInvitationAccepted}
              />
            )}
            {activeTab === 'roles' && (
              <RoleManager
                workspaceId={activeWorkspaceId}
                roles={roles}
                members={members}
                canManage={canManageRoles}
                loading={rolesLoading}
                loadError={rolesError}
                onReload={refreshMembersAndRoles}
              />
            )}
            {activeTab === 'permissions' && userId && (
              <EffectivePermissionsPanel
                workspaceId={activeWorkspaceId}
                currentUserId={userId}
                members={members}
                canInspectOthers={canManageRoles}
              />
            )}
            {activeTab === 'profiles' && canManageMembers && (
              <ProfileFlagsPanel workspaceId={activeWorkspaceId} />
            )}
            {activeTab === 'audit' && canViewAudit && (
              <AuditLogPanel workspaceId={activeWorkspaceId} canView={canViewAudit} />
            )}
          </div>
        </div>
      )}
    </Dialog>
  );
}
