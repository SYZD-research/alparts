import { create } from 'zustand';

interface UiState {
  isAccountSecurityOpen: boolean;
  isChannelManagerOpen: boolean;
  isWorkspaceManagerOpen: boolean;
  isSavedMessagesOpen: boolean;
  dmComposerWorkspaceId: string | null;
  dmComposerInitialMemberIds: string[];
  authorizationRefreshVersion: number;
  isProfileSettingsOpen: boolean;
  /** A member profile being viewed; the warning confirmation is per opening. */
  profileTarget: { workspaceId: string; userId: string } | null;
  openProfileSettings: () => void;
  closeProfileSettings: () => void;
  openMemberProfile: (workspaceId: string, userId: string) => void;
  closeMemberProfile: () => void;
  openAccountSecurity: () => void;
  closeAccountSecurity: () => void;
  openChannelManager: () => void;
  closeChannelManager: () => void;
  openWorkspaceManager: () => void;
  closeWorkspaceManager: () => void;
  openSavedMessages: () => void;
  closeSavedMessages: () => void;
  openDmComposer: (workspaceId: string, initialMemberIds?: string[]) => void;
  closeDmComposer: () => void;
  noteAuthorizationChange: () => void;
  reset: () => void;
}

export const useUiStore = create<UiState>((set) => ({
  isAccountSecurityOpen: false,
  isChannelManagerOpen: false,
  isWorkspaceManagerOpen: false,
  isSavedMessagesOpen: false,
  dmComposerWorkspaceId: null,
  dmComposerInitialMemberIds: [],
  authorizationRefreshVersion: 0,
  isProfileSettingsOpen: false,
  profileTarget: null,
  openProfileSettings: () => set({
    isProfileSettingsOpen: true,
    profileTarget: null,
    isAccountSecurityOpen: false,
    isChannelManagerOpen: false,
    isWorkspaceManagerOpen: false,
    isSavedMessagesOpen: false,
  }),
  closeProfileSettings: () => set({ isProfileSettingsOpen: false }),
  openMemberProfile: (workspaceId, userId) => set({ profileTarget: { workspaceId, userId }, isProfileSettingsOpen: false }),
  closeMemberProfile: () => set({ profileTarget: null }),
  openAccountSecurity: () => set({
    isAccountSecurityOpen: true,
    isChannelManagerOpen: false,
    isWorkspaceManagerOpen: false,
    isSavedMessagesOpen: false,
    dmComposerWorkspaceId: null,
    dmComposerInitialMemberIds: [],
  }),
  closeAccountSecurity: () => set({ isAccountSecurityOpen: false }),
  openChannelManager: () => set({
    isChannelManagerOpen: true,
    isAccountSecurityOpen: false,
    isWorkspaceManagerOpen: false,
    isSavedMessagesOpen: false,
    dmComposerWorkspaceId: null,
    dmComposerInitialMemberIds: [],
  }),
  closeChannelManager: () => set({ isChannelManagerOpen: false }),
  openWorkspaceManager: () => set({
    isWorkspaceManagerOpen: true,
    isSavedMessagesOpen: false,
    isAccountSecurityOpen: false,
    isChannelManagerOpen: false,
    dmComposerWorkspaceId: null,
    dmComposerInitialMemberIds: [],
  }),
  closeWorkspaceManager: () => set({ isWorkspaceManagerOpen: false }),
  openSavedMessages: () => set({
    isSavedMessagesOpen: true,
    isAccountSecurityOpen: false,
    isChannelManagerOpen: false,
    isWorkspaceManagerOpen: false,
    dmComposerWorkspaceId: null,
    dmComposerInitialMemberIds: [],
  }),
  closeSavedMessages: () => set({ isSavedMessagesOpen: false }),
  openDmComposer: (workspaceId, initialMemberIds = []) => set({
    isAccountSecurityOpen: false,
    isChannelManagerOpen: false,
    isWorkspaceManagerOpen: false,
    isSavedMessagesOpen: false,
    dmComposerWorkspaceId: workspaceId,
    dmComposerInitialMemberIds: [...new Set(initialMemberIds)],
  }),
  closeDmComposer: () => set({ dmComposerWorkspaceId: null, dmComposerInitialMemberIds: [] }),
  noteAuthorizationChange: () => set((state) => ({
    authorizationRefreshVersion: state.authorizationRefreshVersion + 1,
  })),
  reset: () => set({
    isAccountSecurityOpen: false,
    isChannelManagerOpen: false,
    isWorkspaceManagerOpen: false,
    isSavedMessagesOpen: false,
    dmComposerWorkspaceId: null,
    dmComposerInitialMemberIds: [],
    authorizationRefreshVersion: 0,
    isProfileSettingsOpen: false,
    profileTarget: null,
  }),
}));
