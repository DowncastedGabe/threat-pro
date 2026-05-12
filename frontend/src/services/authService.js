import httpClient from '../api/httpClient';

export function login(payload) {
  return httpClient.post('/api/v1/auth/login', payload).then((response) => response.data);
}

export function register(payload) {
  return httpClient.post('/api/v1/auth/register', payload).then((response) => response.data);
}

export function refreshToken(refresh_token) {
  return httpClient.post('/api/v1/auth/refresh', { refresh_token }).then((response) => response.data);
}

export function getCurrentUser() {
  return httpClient.get('/api/v1/auth/me').then((response) => response.data);
}

export function logoutRequest(refresh_token) {
  return httpClient.post('/api/v1/auth/logout', { refresh_token }).then((response) => response.data);
}
