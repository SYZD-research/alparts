import { useEffect } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { useAuthStore } from './stores/auth.store';
import { LoginPage } from './components/auth/LoginPage';
import { AppLayout } from './components/layout/AppLayout';

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { user, isLoading } = useAuthStore();

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-screen bg-discord-bg">
        <div className="text-discord-muted">Loading...</div>
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
}

export default function App() {
  const { loadUser, token } = useAuthStore();

  useEffect(() => {
    if (token) {
      loadUser();
    }
  }, []);

  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/*"
        element={
          <ProtectedRoute>
            <AppLayout />
          </ProtectedRoute>
        }
      />
    </Routes>
  );
}
