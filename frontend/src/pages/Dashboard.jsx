import React, { useEffect, useState } from 'react';
import {
  Container, Stack, Typography, Box, Snackbar, Alert, Skeleton, Grid,
} from '@mui/material';
import BugReportIcon from '@mui/icons-material/BugReport';
import DashboardIcon from '@mui/icons-material/Dashboard';
import api from '../api';
import StatsGrid, { StatsGridSkeleton } from '../components/StatsGrid';
import RiskChart, { RiskChartSkeleton }   from '../components/RiskChart';
import HistoryTable, { HistoryTableSkeleton } from '../components/HistoryTable';
import SiteHistoryTable, { SiteHistoryTableSkeleton } from '../components/SiteHistoryTable';
import SandBox from './SandBox';
import LanguageIcon from '@mui/icons-material/Language';
import RouterIcon from '@mui/icons-material/Router';
import { Tab, Tabs as MuiTabs } from '@mui/material';

function PageHeader({ total }) {
  return (
    <Box sx={{ mb: 5 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 1 }}>
        <Box sx={{
          width: 44, height: 44, borderRadius: '12px', display: 'flex', alignItems: 'center', justifyContent: 'center',
          background: 'linear-gradient(135deg, rgba(0,212,255,0.2), rgba(0,255,157,0.08))',
          border: '1px solid rgba(0,212,255,0.25)',
        }}>
          <DashboardIcon sx={{ color: 'primary.main', fontSize: 22 }} />
        </Box>
        <Box>
          <Typography variant="h4" sx={{ fontWeight: 800, lineHeight: 1.1 }}>
            Dashboard Global
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Visão geral de todas as análises de ameaças registradas
          </Typography>
        </Box>
      </Box>
    </Box>
  );
}

function EmptyState() {
  return (
    <Box sx={{
      textAlign: 'center', py: 10, px: 4,
      border: '1px dashed rgba(0,212,255,0.15)',
      borderRadius: 3,
      background: 'rgba(0,212,255,0.02)',
    }}>
      <DashboardIcon sx={{ fontSize: 56, color: 'rgba(0,212,255,0.2)', mb: 2 }} />
      <Typography variant="h6" sx={{ fontWeight: 700, mb: 1 }}>
        Nenhuma análise encontrada
      </Typography>
      <Typography variant="body2" color="text.secondary">
        Realize um escaneamento de IP ou Site para que os registros apareçam aqui.
      </Typography>
    </Box>
  );
}

export default function Dashboard() {
  const [historicoIPs, setHistoricoIPs] = useState([]);
  const [historicoSites, setHistoricoSites] = useState([]);
  const [loading, setLoading]     = useState(true);
  const [error, setError]         = useState('');
  const [tabIndex, setTabIndex]   = useState(0);

  const carregarHistoricoSites = async (filtros = {}) => {
    try {
      const res = await api.get('/historico/sites', {
        params: {
          pagina: 1,
          por_pagina: 100,
          ...filtros,
        },
      });
      setHistoricoSites(res.data.dados || []);
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Erro ao filtrar historico de sites.');
    }
  };

  useEffect(() => {
    (async () => {
      try {
        const [resIPs, resSites] = await Promise.all([
          api.get('/historico/'),
          api.get('/historico/sites', { params: { pagina: 1, por_pagina: 100 } })
        ]);
        setHistoricoIPs(resIPs.data.dados || []);
        setHistoricoSites(resSites.data.dados || []);
      } catch (err) {
        const msg = err.response?.status === 401 || err.response?.status === 403
          ? 'Erro de autenticação: verifique a API Key no .env.'
          : err.response?.data?.detail || err.message || 'Erro ao carregar histórico.';
        setError(msg);
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  return (
    <Container maxWidth="xl" sx={{ py: 5, px: { xs: 2, sm: 3 } }}>
      <PageHeader />

      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 4 }}>
        <MuiTabs value={tabIndex} onChange={(_, v) => setTabIndex(v)} sx={{ '& .MuiTab-root': { minHeight: 48 } }}>
          <Tab icon={<RouterIcon sx={{ mr: 1, fontSize: 20 }} />} iconPosition="start" label="Histórico de IPs" />
          <Tab icon={<LanguageIcon sx={{ mr: 1, fontSize: 20 }} />} iconPosition="start" label="Histórico de Sites" />
          <Tab
            icon={<BugReportIcon sx={{ mr: 1, fontSize: 20, color: tabIndex === 2 ? '#ff1744' : undefined }} />}
            iconPosition="start"
            label="SandBox"
            sx={{ '&.Mui-selected': { color: '#ff1744' } }}
          />
        </MuiTabs>
      </Box>

      {tabIndex === 0 && (
        loading ? (
          <Stack spacing={4}>
            <StatsGridSkeleton />
            <RiskChartSkeleton />
            <HistoryTableSkeleton />
          </Stack>
        ) : historicoIPs.length === 0 ? (
          <EmptyState />
        ) : (
          <Stack spacing={4}>
            <StatsGrid historico={historicoIPs} />
            <RiskChart  historico={historicoIPs} />
            <HistoryTable historico={historicoIPs} />
          </Stack>
        )
      )}

      {tabIndex === 1 && (
        loading ? (
          <Stack spacing={4}>
            <SiteHistoryTableSkeleton />
          </Stack>
        ) : historicoSites.length === 0 ? (
          <EmptyState />
        ) : (
          <Stack spacing={4}>
            <SiteHistoryTable historico={historicoSites} onFilterChange={carregarHistoricoSites} />
          </Stack>
        )
      )}

      {tabIndex === 2 && <SandBox />}

      <Snackbar open={Boolean(error)} anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}>
        <Alert severity="error" variant="filled" sx={{ fontWeight: 600, borderRadius: 2 }}>
          {error}
        </Alert>
      </Snackbar>
    </Container>
  );
}
