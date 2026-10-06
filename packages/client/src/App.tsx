import { useEffect, useState, useCallback } from 'react';
import { Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { useAuthStore } from './stores/auth.store';
import { LoginPage } from './components/auth/LoginPage';
import { getActiveDevice } from './services/crypto.service';
import { DeviceApprovalPage } from './components/security/DeviceApprovalPage';
import { StepUpDialog } from './components/security/StepUpDialog';
import { AppLayout } from './components/layout/AppLayout';
import { useT } from './i18n';

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { user, isLoading, isInitialized } = useAuthStore();
  const location = useLocation();
  const t = useT();
  const [, forceRefresh] = useState(0);
  const approved = useCallback(() => forceRefresh((n) => n + 1), []);

  if (isLoading || !isInitialized) {
    return (
      <div className="flex items-center justify-center h-screen bg-discord-bg">
        <div className="text-discord-muted">{t('読み込み中…')}</div>
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace state={{ returnTo: location.pathname }} />;
  }

  if (!getActiveDevice().approved) return <DeviceApprovalPage onApproved={approved} />;
  return <>{children}</>;
}

export default function App() {
  const { loadUser } = useAuthStore();

  useEffect(() => {
    void loadUser();
  }, []);

  return (
    <>
      <StepUpDialog />
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route
          path="/workspaces/:workspaceId/channels/:channelId/messages/:messageId"
          element={
            <ProtectedRoute>
              <AppLayout />
            </ProtectedRoute>
          }
        />
        <Route
          path="/*"
          element={
            <ProtectedRoute>
              <AppLayout />
            </ProtectedRoute>
          }
        />
      </Routes>
    </>
  );
}
