import { useCallback, useEffect, useState } from 'react';

import { listSiteHistory } from '../../../services/siteHistoryService';

export function useSiteHistory(initialFilters = { pagina: 1, por_pagina: 100 }) {
  const [filters, setFilters] = useState(initialFilters);
  const [data, setData] = useState({ dados: [], total: 0, pagina: 1, por_pagina: 100 });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const load = useCallback(async (nextFilters = filters) => {
    setLoading(true);
    setError('');
    try {
      const result = await listSiteHistory(nextFilters);
      setData(result);
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Erro ao carregar historico de sites.');
    } finally {
      setLoading(false);
    }
  }, [filters]);

  useEffect(() => {
    load(filters);
  }, [load, filters]);

  const updateFilters = (nextFilters) => {
    setFilters({ pagina: 1, por_pagina: 100, ...nextFilters });
  };

  return { data, loading, error, filters, setFilters: updateFilters, reload: load };
}
