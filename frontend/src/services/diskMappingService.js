import httpClient from '../api/httpClient';

export function scanDiskMapping(payload = {}) {
  return httpClient.post('/api/v1/disk-mapping/scan', payload).then((response) => response.data);
}
