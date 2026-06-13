import { create } from 'zustand';
import type { User } from '../types';

const TOKEN_KEY = 'vtrace_access_token';

interface AuthState {
  user: User | null;
  accessToken: string | null;
  isAuthenticated: boolean;
  setAuth: (user: User, accessToken: string) => void;
  clearAuth: () => void;
}

const initialToken = localStorage.getItem(TOKEN_KEY);

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  accessToken: initialToken,
  isAuthenticated: Boolean(initialToken),
  setAuth: (user, accessToken) => {
    console.log('[DEBUG] authStore: setAuth action called with user:', user, 'token:', accessToken ? accessToken.substring(0, 15) + '...' : null);
    localStorage.setItem(TOKEN_KEY, accessToken);
    set({ user, accessToken, isAuthenticated: true });
    console.log('[DEBUG] authStore: setAuth state updated');
  },
  clearAuth: () => {
    console.log('[DEBUG] authStore: clearAuth action called');
    localStorage.removeItem(TOKEN_KEY);
    set({ user: null, accessToken: null, isAuthenticated: false });
    console.log('[DEBUG] authStore: clearAuth state updated');
  },
}));

export { TOKEN_KEY };
