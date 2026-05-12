import httpClient from '../api/httpClient';

export function listSiteHistory(params = {}) {
  return httpClient.get('/historico/sites', { params }).then((response) => response.data);
}
