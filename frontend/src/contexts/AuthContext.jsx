import React, { createContext, useCallback, useEffect, useMemo, useState } from 'react';

import { getCurrentUser, login as loginRequest, logoutRequest, refreshToken, register as registerRequest } from '../services/authService';
import { clearSession, getRefreshToken, getStoredUser, persistSession } from '../features/auth/tokenStorage';

export const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(getStoredUser());
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const applySession = useCallback((session) => {
    persistSession(session);
    setUser(session.user);
  }, []);

  const login = useCallback(async (payload) => {
    setError('');
    const session = await loginRequest(payload);
    applySession(session);
    return session;
  }, [applySession]);

  const register = useCallback(async (payload) => {
    setError('');
    const session = await registerRequest(payload);
    applySession(session);
    return session;
  }, [applySession]);

  const logout = useCallback(async () => {
    try {
      const refresh = getRefreshToken();
      if (refresh) {
        await logoutRequest(refresh);
      }
    } catch {
      // Client-side logout remains authoritative for stateless JWT.
    }
    clearSession();
    setUser(null);
  }, []);

  const restoreSession = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const refresh = getRefreshToken();
      if (!refresh) {
        setUser(null);
        return;
      }
      const session = await refreshToken(refresh);
      applySession(session);
      const current = await getCurrentUser();
      setUser(current);
    } catch (err) {
      clearSession();
      setUser(null);
      setError(err.response?.data?.detail || 'Sessao expirada.');
    } finally {
      setLoading(false);
    }
  }, [applySession]);

  useEffect(() => {
    restoreSession();
  }, [restoreSession]);

  const value = useMemo(() => ({
    user,
    loading,
    error,
    isAuthenticated: Boolean(user),
    isAdmin: user?.role === 'admin',
    login,
    register,
    logout,
    restoreSession,
  }), [error, loading, login, logout, register, restoreSession, user]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
