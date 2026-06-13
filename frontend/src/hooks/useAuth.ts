import { useAuthStore } from '../store/authStore';

export function useAuth() {
  const user = useAuthStore((state) => state.user);
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);

  const isAdmin = user?.role === 'admin';
  const isModerator = user?.role === 'moderator' || user?.role === 'admin';

  return {
    user,
    isAuthenticated,
    isAdmin,
    isModerator,
  };
}
