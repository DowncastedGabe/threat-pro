import React from 'react';
import { Grid, Card, CardContent, Typography, Box, Skeleton } from '@mui/material';
import {
  PieChart, Pie, Cell, Tooltip as PieTooltip, Legend, ResponsiveContainer,
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip as AreaTooltip,
} from 'recharts';
import { format, parseISO } from 'date-fns';

const RISK_PALETTE = {
  critico:     '#ff3b5c',
  alto:        '#ffb830',
  medio:       '#ffd60a',
  baixo:       '#00ff9d',
  desconhecido:'#8e8e93',
};

const TOOLTIP_STYLE = {
  contentStyle: { backgroundColor: '#0d1421', borderColor: 'rgba(0,212,255,0.2)', borderRadius: 10, color: '#fff', fontSize: '0.85rem' },
  itemStyle: { color: '#fff' },
};

const CustomPieLabel = ({ cx, cy, total }) => (
  <>
    <text x={cx} y={cy - 8} textAnchor="middle" fill="rgba(255,255,255,0.9)" style={{ fontSize: 26, fontWeight: 800, fontFamily: 'Inter' }}>
      {total}
    </text>
    <text x={cx} y={cy + 14} textAnchor="middle" fill="rgba(255,255,255,0.4)" style={{ fontSize: 11, fontFamily: 'Inter', letterSpacing: 2, textTransform: 'uppercase' }}>
      Total
    </text>
  </>
);

export function RiskChartSkeleton() {
  return (
    <Grid container spacing={3} sx={{ mb: 4 }}>
      <Grid item xs={12} md={4}>
        <Card sx={{ height: 340 }}><CardContent><Skeleton variant="circular" width={200} height={200} sx={{ mx: 'auto', mt: 2 }} /></CardContent></Card>
      </Grid>
      <Grid item xs={12} md={8}>
        <Card sx={{ height: 340 }}><CardContent><Skeleton variant="rectangular" height={260} sx={{ mt: 2, borderRadius: 2 }} /></CardContent></Card>
      </Grid>
    </Grid>
  );
}

export default function RiskChart({ historico }) {
  // Pie data
  const riscoCount = { critico: 0, alto: 0, medio: 0, baixo: 0, desconhecido: 0 };
  historico.forEach(item => {
    const r = (item.risco || 'desconhecido').toLowerCase();
    if (r in riscoCount) riscoCount[r]++;
    else riscoCount.desconhecido++;
  });

  const pieData = Object.entries(riscoCount)
    .filter(([, v]) => v > 0)
    .map(([key, value]) => ({ name: key.charAt(0).toUpperCase() + key.slice(1), value, color: RISK_PALETTE[key] }));

  const total = historico.length;

  // Area / timeline data
  const timelineMap = {};
  historico.forEach(item => {
    try {
      const d = format(parseISO(item.timestamp_auditoria), 'dd/MM');
      timelineMap[d] = (timelineMap[d] || 0) + 1;
    } catch (_) {}
  });
  const areaData = Object.keys(timelineMap).sort().map(date => ({ date, analises: timelineMap[date] }));

  return (
    <Grid container spacing={3} sx={{ mb: 4 }}>
      {/* PIE CHART */}
      <Grid item xs={12} md={4}>
        <Card sx={{ height: '100%' }}>
          <CardContent sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>Distribuição de Riscos</Typography>
            <Box sx={{ height: 280, position: 'relative' }}>
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="45%"
                    innerRadius={68}
                    outerRadius={90}
                    stroke="none"
                    paddingAngle={3}
                  >
                    {pieData.map((entry, i) => (
                      <Cell key={i} fill={entry.color} />
                    ))}
                    {/* Center label rendered as custom label */}
                  </Pie>
                  <PieTooltip {...TOOLTIP_STYLE} />
                  <Legend
                    iconType="circle"
                    iconSize={8}
                    formatter={(v) => <span style={{ fontSize: '0.78rem', color: 'rgba(255,255,255,0.7)' }}>{v}</span>}
                  />
                </PieChart>
              </ResponsiveContainer>
              {/* Center label overlay */}
              <Box sx={{
                position: 'absolute', top: '37%', left: '50%', transform: 'translate(-50%, -50%)',
                textAlign: 'center', pointerEvents: 'none',
              }}>
                <Typography variant="h3" sx={{ fontWeight: 800, lineHeight: 1, color: 'primary.main' }}>{total}</Typography>
                <Typography variant="caption" color="text.secondary">Total</Typography>
              </Box>
            </Box>
          </CardContent>
        </Card>
      </Grid>

      {/* AREA CHART */}
      <Grid item xs={12} md={8}>
        <Card sx={{ height: '100%' }}>
          <CardContent sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>Volume de Análises por Dia</Typography>
            <Box sx={{ height: 280 }}>
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={areaData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="gradCyan" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor="#00d4ff" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#00d4ff" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                  <XAxis dataKey="date" stroke="rgba(255,255,255,0.3)" tick={{ fontSize: 11 }} />
                  <YAxis stroke="rgba(255,255,255,0.3)" tick={{ fontSize: 11 }} allowDecimals={false} />
                  <AreaTooltip {...TOOLTIP_STYLE} />
                  <Area
                    type="monotone"
                    dataKey="analises"
                    stroke="#00d4ff"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#gradCyan)"
                    dot={{ r: 3, fill: '#00d4ff', strokeWidth: 0 }}
                    activeDot={{ r: 5, fill: '#00d4ff', stroke: 'rgba(0,212,255,0.4)', strokeWidth: 4 }}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </Box>
          </CardContent>
        </Card>
      </Grid>
    </Grid>
  );
}
