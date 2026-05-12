import { createContext, useContext } from 'react';

export const AuthContext = createContext({
  user: null,
  token: null,
  setSession: () => {},
  clearSession: () => {},
});

export function useAuthStore() {
  return useContext(AuthContext);
}
