import axios, { AxiosError, type InternalAxiosRequestConfig } from 'axios';
import { TOKEN_KEY, useAuthStore } from '../store/authStore';

interface RefreshResponse {
  accessToken: string;
}

interface RetryRequestConfig extends InternalAxiosRequestConfig {
  _retry?: boolean;
}

const getBaseURL = () => {
  const envUrl = import.meta.env.VITE_API_URL;
  if (typeof window !== 'undefined') {
    const hostname = window.location.hostname;
    // Align host dynamically (localhost or 127.0.0.1) to ensure SameSite cookies work
    if (hostname === 'localhost') {
      return 'http://localhost:5000/api';
    }
    if (hostname === '127.0.0.1') {
      return 'http://127.0.0.1:5000/api';
    }
  }
  return envUrl || 'http://127.0.0.1:5000/api';
};

const baseURL = getBaseURL();

const apiClient = axios.create({
  baseURL,
  withCredentials: true,
});

const refreshClient = axios.create({
  baseURL,
  withCredentials: true,
});

let refreshPromise: Promise<string | null> | null = null;

apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem(TOKEN_KEY);
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

async function runRefresh(): Promise<string | null> {
  if (!refreshPromise) {
    refreshPromise = refreshClient
      .post<RefreshResponse>('/auth/refresh')
      .then((response) => {
        const newToken = response.data.accessToken;
        localStorage.setItem(TOKEN_KEY, newToken);
        useAuthStore.setState((state) => ({
          ...state,
          accessToken: newToken,
          isAuthenticated: true,
        }));
        return newToken;
      })
      .catch(() => {
        localStorage.removeItem(TOKEN_KEY);
        useAuthStore.getState().clearAuth();
        if (window.location.pathname !== '/login') {
          window.location.href = '/login';
        }
        return null;
      })
      .finally(() => {
        refreshPromise = null;
      });
  }

  return refreshPromise;
}

apiClient.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as RetryRequestConfig | undefined;

    if (!originalRequest) {
      return Promise.reject(error);
    }

    const statusCode = error.response?.status;
    const requestUrl = originalRequest.url || '';
    const isRefreshEndpoint = requestUrl.includes('/auth/refresh');

    if (statusCode === 401 && !originalRequest._retry && !isRefreshEndpoint) {
      originalRequest._retry = true;
      const refreshedToken = await runRefresh();

      if (refreshedToken) {
        originalRequest.headers.Authorization = `Bearer ${refreshedToken}`;
        return apiClient(originalRequest);
      }
    }

    return Promise.reject(error);
  }
);

export default apiClient;
