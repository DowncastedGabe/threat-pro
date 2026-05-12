import httpClient from '../api/httpClient';

export function scanRouterHealth(payload = {}) {
  return httpClient.post('/api/v1/router-health/scan', payload).then((response) => response.data);
}
