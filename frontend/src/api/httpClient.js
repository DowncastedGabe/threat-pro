import axios from 'axios';
import { clearSession, getRefreshToken, persistSession } from '../features/auth/tokenStorage';

const API_BASE =
  import.meta.env.VITE_API_BASE_URL ||
  import.meta.env.VITE_API_BASE ||
  import.meta.env.VITE_API_URL ||
  'http://localhost:8000';

const API_KEY = import.meta.env.VITE_API_KEY || '';

const httpClient = axios.create({
  baseURL: API_BASE,
  timeout: 30000,
});

httpClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  if (API_KEY) {
    config.headers['x-api-key'] = API_KEY;
  }
  return config;
});

let refreshPromise = null;

httpClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    const isAuthEndpoint = originalRequest?.url?.includes('/auth/login') ||
      originalRequest?.url?.includes('/auth/register') ||
      originalRequest?.url?.includes('/auth/refresh');

    if (error.response?.status !== 401 || originalRequest?._retry || isAuthEndpoint) {
      return Promise.reject(error);
    }

    const refresh = getRefreshToken();
    if (!refresh) {
      clearSession();
      return Promise.reject(error);
    }

    originalRequest._retry = true;
    refreshPromise = refreshPromise || httpClient.post('/api/v1/auth/refresh', { refresh_token: refresh })
      .then((response) => {
        persistSession(response.data);
        return response.data.access_token;
      })
      .finally(() => {
        refreshPromise = null;
      });

    const accessToken = await refreshPromise;
    originalRequest.headers.Authorization = `Bearer ${accessToken}`;
    return httpClient(originalRequest);
  }
);

export default httpClient;
