import React, { createContext, useContext, useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Login from './pages/Login.jsx';
import Dashboard from './pages/Dashboard.jsx';
import Scan from './pages/Scan.jsx';
import { checkAuthStatus } from './api/client.js';

// ── Auth Context ──────────────────────────────────────────────────────────────
export const AuthContext = createContext(null);

export function useAuth() {
  return useContext(AuthContext);
}

function AuthProvider({ children }) {
  const [token, setToken] = useState(() => localStorage.getItem('cg_token'));
  const [authRequired, setAuthRequired] = useState(null); // null = loading

  useEffect(() => {
    checkAuthStatus().then((required) => {
      setAuthRequired(required);
      // If auth is not required, clear any stale token requirement
      if (!required) {
        // Still set a dummy token so protected routes pass
        if (!token) {
          localStorage.setItem('cg_token', 'no-auth');
          setToken('no-auth');
        }
      }
    });
  }, []);

  const login = (newToken) => {
    localStorage.setItem('cg_token', newToken);
    setToken(newToken);
  };

  const logout = () => {
    localStorage.removeItem('cg_token');
    setToken(null);
  };

  const isAuthenticated = () => {
    if (authRequired === false) return true;
    return !!token;
  };

  return (
    <AuthContext.Provider value={{ token, authRequired, login, logout, isAuthenticated }}>
      {children}
    </AuthContext.Provider>
  );
}

// ── Protected Route ───────────────────────────────────────────────────────────
function ProtectedRoute({ children }) {
  const { isAuthenticated, authRequired } = useAuth();

  // Still loading auth status
  if (authRequired === null) {
    return (
      <div className="flex items-center justify-center h-screen bg-bg">
        <div className="flex flex-col items-center gap-3">
          <div className="w-8 h-8 border-2 border-accent border-t-transparent rounded-full animate-spin" />
          <span className="text-slate-500 text-sm">Loading...</span>
        </div>
      </div>
    );
  }

  if (!isAuthenticated()) {
    return <Navigate to="/login" replace />;
  }

  return children;
}

// ── App ───────────────────────────────────────────────────────────────────────
export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route
            path="/dashboard"
            element={
              <ProtectedRoute>
                <Dashboard />
              </ProtectedRoute>
            }
          />
          <Route
            path="/scan"
            element={
              <ProtectedRoute>
                <Scan />
              </ProtectedRoute>
            }
          />
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}
