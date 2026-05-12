import React from 'react';
import { Grid, Card, CardContent, Typography, Box, Skeleton, alpha } from '@mui/material';
import AssignmentIcon from '@mui/icons-material/Assignment';
import GppBadIcon from '@mui/icons-material/GppBad';
import TrendingUpIcon from '@mui/icons-material/TrendingUp';
import PublicIcon from '@mui/icons-material/Public';
import TaskAltIcon from '@mui/icons-material/TaskAlt';

const STAT_CONFIGS = [
  {
    key: 'total',
    label: 'Total de Análises',
    icon: AssignmentIcon,
    color: '#00d4ff',
    getValue: (h) => h.length,
  },
  {
    key: 'criticos',
    label: 'Ameaças Críticas',
    icon: GppBadIcon,
    color: '#ff3b5c',
    getValue: (h) => h.filter(i => i.risco === 'critico').length,
  },
  {
    key: 'seguros',
    label: 'IPs Seguros',
    icon: TaskAltIcon,
    color: '#00ff9d',
    getValue: (h) => h.filter(i => i.risco === 'baixo').length,
  },
  {
    key: 'media',
    label: 'Score Médio de Risco',
    icon: TrendingUpIcon,
    color: '#ffb830',
    getValue: (h) => {
      if (!h.length) return 0;
      return (h.reduce((acc, i) => acc + (i.score || 0), 0) / h.length).toFixed(1);
    },
    suffix: '%',
  },
  {
    key: 'pais',
    label: 'Top País de Origem',
    icon: PublicIcon,
    color: '#bf5af2',
    getValue: (h) => {
      const counts = {};
      h.forEach(i => { if (i.pais) counts[i.pais] = (counts[i.pais] || 0) + 1; });
      if (!Object.keys(counts).length) return 'N/A';
      return Object.keys(counts).reduce((a, b) => counts[a] > counts[b] ? a : b);
    },
  },
];

function StatCard({ config, historico }) {
  const Icon = config.icon;
  const value = config.getValue(historico);

  return (
    <Card sx={{ height: '100%', position: 'relative', overflow: 'hidden' }}>
      {/* Top accent bar */}
      <Box sx={{
        position: 'absolute', top: 0, left: 0, right: 0, height: 2,
        background: `linear-gradient(90deg, ${config.color}, transparent)`,
      }} />
      <CardContent sx={{ p: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', mb: 2 }}>
          <Typography variant="caption" color="text.secondary" sx={{ lineHeight: 1.4 }}>
            {config.label}
          </Typography>
          <Box sx={{
            width: 40, height: 40, borderRadius: '10px', display: 'flex', alignItems: 'center', justifyContent: 'center',
            backgroundColor: alpha(config.color, 0.12),
            border: `1px solid ${alpha(config.color, 0.2)}`,
            flexShrink: 0, ml: 1,
          }}>
            <Icon sx={{ color: config.color, fontSize: 20 }} />
          </Box>
        </Box>
        <Typography
          variant="h3"
          sx={{
            fontWeight: 800, fontSize: typeof value === 'string' && value.length > 5 ? '1.5rem' : '2.2rem',
            color: config.color, lineHeight: 1, letterSpacing: '-0.02em',
          }}
        >
          {value}{config.suffix || ''}
        </Typography>
      </CardContent>
    </Card>
  );
}

export function StatsGridSkeleton() {
  return (
    <Grid container spacing={3} sx={{ mb: 4 }}>
      {[1, 2, 3, 4, 5].map(i => (
        <Grid item xs={12} sm={6} md={4} lg key={i}>
          <Card sx={{ height: 130 }}>
            <CardContent sx={{ p: 3 }}>
              <Skeleton variant="text" width="60%" height={16} sx={{ mb: 2 }} />
              <Skeleton variant="text" width="40%" height={48} />
            </CardContent>
          </Card>
        </Grid>
      ))}
    </Grid>
  );
}

export default function StatsGrid({ historico }) {
  return (
    <Grid container spacing={3} sx={{ mb: 4 }}>
      {STAT_CONFIGS.map((config) => (
        <Grid item xs={12} sm={6} md={4} lg key={config.key}>
          <StatCard config={config} historico={historico} />
        </Grid>
      ))}
    </Grid>
  );
}
