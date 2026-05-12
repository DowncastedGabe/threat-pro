/**
 * HeatMap.jsx — Mapa de Calor Global de IPs Analisados
 *
 * Otimizações de performance:
 *  - React.memo  → evita re-render do componente quando props/state do pai mudam
 *  - useMemo     → memoriza o cálculo de escala de cor e dados transformados
 *  - O ComposableMap e Geographies são pesados; o JSON do mapa é carregado
 *    uma única vez via URL (CDN) e cacheado pelo browser.
 */

import React, { useState, useEffect, useMemo, useCallback } from 'react';
import {
  ComposableMap,
  Geographies,
  Geography,
  Marker,
  ZoomableGroup,
} from 'react-simple-maps';
import {
  Box, Container, Typography, CircularProgress, Alert,
  Tooltip, Chip, Stack, alpha, Paper, IconButton,
} from '@mui/material';
import PublicIcon from '@mui/icons-material/Public';
import MyLocationIcon from '@mui/icons-material/MyLocation';
import api from '../api';

// TopoJSON leve do Natural Earth (110m resolução, ~110kb)
const GEO_URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json';

/* ── Helpers ──────────────────────────────────────────────────────────────── */

const RISCO_CONFIG = {
  critico:     { color: '#ff3b5c', label: 'Crítico',     ordem: 4 },
  alto:        { color: '#ff6b35', label: 'Alto',        ordem: 3 },
  medio:       { color: '#ffb830', label: 'Médio',       ordem: 2 },
  baixo:       { color: '#00ff9d', label: 'Baixo',       ordem: 1 },
  desconhecido:{ color: '#6e6e8a', label: 'Desconhecido',ordem: 0 },
  agendado:    { color: '#00d4ff', label: 'Agendado',    ordem: 0 },
};

function getRiscoColor(risco) {
  return (RISCO_CONFIG[risco] || RISCO_CONFIG.desconhecido).color;
}

function getRiscoRadius(score) {
  // Raio entre 4 e 12px proporcional ao score AbuseIPDB
  return 4 + Math.min(score / 100, 1) * 8;
}

/* ── Componente de marcador — memorizado individualmente ─────────────────── */
const IpMarker = React.memo(function IpMarker({ ponto, onHover, onLeave }) {
  const color  = getRiscoColor(ponto.risco);
  const radius = getRiscoRadius(ponto.score);

  return (
    <Marker
      coordinates={[ponto.longitude, ponto.latitude]}
      onMouseEnter={() => onHover(ponto)}
      onMouseLeave={onLeave}
    >
      {/* Anel pulsante */}
      <circle r={radius + 4} fill={color} fillOpacity={0.15} />
      {/* Ponto central */}
      <circle
        r={radius}
        fill={color}
        fillOpacity={0.9}
        stroke="#0a0a1a"
        strokeWidth={0.8}
        style={{ cursor: 'pointer' }}
      />
    </Marker>
  );
});

/* ── Legenda ──────────────────────────────────────────────────────────────── */
const MapLegend = React.memo(function MapLegend() {
  return (
    <Paper
      elevation={0}
      sx={{
        position: 'absolute',
        bottom: 16,
        left: 16,
        p: 1.5,
        borderRadius: 2,
        backgroundColor: alpha('#0d0d1a', 0.92),
        border: '1px solid rgba(255,255,255,0.08)',
        backdropFilter: 'blur(8px)',
      }}
    >
      <Typography variant="caption" color="text.secondary" sx={{ mb: 1, display: 'block', fontWeight: 700 }}>
        Nível de Risco
      </Typography>
      <Stack spacing={0.6}>
        {Object.entries(RISCO_CONFIG)
          .filter(([k]) => !['agendado', 'desconhecido'].includes(k))
          .sort(([, a], [, b]) => b.ordem - a.ordem)
          .map(([key, cfg]) => (
            <Box key={key} sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Box sx={{ width: 10, height: 10, borderRadius: '50%', backgroundColor: cfg.color, flexShrink: 0 }} />
              <Typography variant="caption" color="text.secondary">{cfg.label}</Typography>
            </Box>
          ))}
      </Stack>
    </Paper>
  );
});

/* ── Tooltip flutuante ────────────────────────────────────────────────────── */
const HoverCard = React.memo(function HoverCard({ ponto }) {
  if (!ponto) return null;
  const color = getRiscoColor(ponto.risco);
  return (
    <Paper
      elevation={0}
      sx={{
        position: 'absolute',
        top: 16,
        right: 16,
        p: 2,
        minWidth: 200,
        borderRadius: 2,
        backgroundColor: alpha('#0d0d1a', 0.95),
        border: `1px solid ${alpha(color, 0.4)}`,
        backdropFilter: 'blur(12px)',
      }}
    >
      <Typography variant="body2" sx={{ fontFamily: '"JetBrains Mono", monospace', fontWeight: 700, color }}>
        {ponto.ip}
      </Typography>
      <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 0.5 }}>
        {ponto.pais || 'País desconhecido'}
      </Typography>
      <Box sx={{ display: 'flex', gap: 1, mt: 1, flexWrap: 'wrap' }}>
        <Chip
          label={(RISCO_CONFIG[ponto.risco] || RISCO_CONFIG.desconhecido).label}
          size="small"
          sx={{ backgroundColor: alpha(color, 0.15), color, fontWeight: 700, fontSize: '0.68rem' }}
        />
        <Chip
          label={`Score: ${ponto.score}`}
          size="small"
          variant="outlined"
          sx={{ borderColor: alpha(color, 0.3), color: 'text.secondary', fontSize: '0.68rem' }}
        />
      </Box>
    </Paper>
  );
});

/* ── Componente principal — React.memo evita re-renders do pai ───────────── */
const HeatMap = React.memo(function HeatMap() {
  const [pontos, setPontos]       = useState([]);
  const [loading, setLoading]     = useState(true);
  const [error, setError]         = useState('');
  const [hoveredPonto, setHoveredPonto] = useState(null);
  const [zoom, setZoom]           = useState(1);
  const [center, setCenter]       = useState([0, 20]);

  useEffect(() => {
    let cancelado = false;
    async function fetchPontos() {
      try {
        const res = await api.get('/mapa/');
        if (!cancelado) setPontos(res.data);
      } catch (err) {
        if (!cancelado) {
          setError(err.response?.data?.detail || 'Erro ao carregar dados do mapa.');
        }
      } finally {
        if (!cancelado) setLoading(false);
      }
    }
    fetchPontos();
    return () => { cancelado = true; };
  }, []);

  // useMemo: evita reordenar marcadores a cada render
  const pontosOrdenados = useMemo(
    () => [...pontos].sort((a, b) => {
      const oa = RISCO_CONFIG[a.risco]?.ordem ?? 0;
      const ob = RISCO_CONFIG[b.risco]?.ordem ?? 0;
      return oa - ob; // críticos renderizados por cima
    }),
    [pontos],
  );

  const handleHover  = useCallback((p) => setHoveredPonto(p), []);
  const handleLeave  = useCallback(() => setHoveredPonto(null), []);
  const handleReset  = useCallback(() => { setZoom(1); setCenter([0, 20]); }, []);

  const estatsPorRisco = useMemo(() => {
    const counts = {};
    for (const p of pontos) {
      counts[p.risco] = (counts[p.risco] || 0) + 1;
    }
    return counts;
  }, [pontos]);

  return (
    <Container maxWidth="xl" sx={{ py: 5, px: { xs: 2, sm: 3 } }}>
      {/* Hero */}
      <Box sx={{ textAlign: 'center', mb: 4 }}>
        <Box sx={{
          display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
          width: 64, height: 64, borderRadius: '18px', mb: 2.5,
          background: 'linear-gradient(135deg, rgba(0,212,255,0.15), rgba(0,255,157,0.05))',
          border: '1px solid rgba(0,212,255,0.3)',
        }}>
          <PublicIcon sx={{ color: 'primary.main', fontSize: 32 }} />
        </Box>
        <Typography variant="h4" gutterBottom sx={{ fontWeight: 800 }}>
          Mapa de Ameaças Global
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ maxWidth: 520, mx: 'auto' }}>
          Geolocalização de todos os IPs analisados. Arraste e use scroll para navegar.
        </Typography>
      </Box>

      {/* Stats */}
      {!loading && pontos.length > 0 && (
        <Stack direction="row" spacing={1} sx={{ mb: 3, flexWrap: 'wrap', justifyContent: 'center', gap: 1 }}>
          <Chip label={`${pontos.length} IPs`} sx={{ fontWeight: 700, backgroundColor: alpha('#00d4ff', 0.12), color: 'primary.main' }} />
          {Object.entries(estatsPorRisco).map(([risco, count]) => {
            const color = getRiscoColor(risco);
            return (
              <Chip
                key={risco}
                label={`${(RISCO_CONFIG[risco] || RISCO_CONFIG.desconhecido).label}: ${count}`}
                size="small"
                sx={{ backgroundColor: alpha(color, 0.1), color, fontWeight: 600, fontSize: '0.75rem' }}
              />
            );
          })}
        </Stack>
      )}

      {/* Mapa */}
      {loading && (
        <Box sx={{ display: 'flex', justifyContent: 'center', py: 10 }}>
          <CircularProgress size={48} />
        </Box>
      )}

      {error && (
        <Alert severity="error" sx={{ maxWidth: 600, mx: 'auto' }}>{error}</Alert>
      )}

      {!loading && !error && (
        <Paper
          elevation={0}
          sx={{
            position: 'relative',
            borderRadius: 3,
            overflow: 'hidden',
            border: '1px solid rgba(255,255,255,0.06)',
            backgroundColor: '#060612',
            height: { xs: 340, sm: 480, md: 580 },
          }}
        >
          <ComposableMap
            projection="geoMercator"
            style={{ width: '100%', height: '100%' }}
          >
            <ZoomableGroup
              zoom={zoom}
              center={center}
              onMoveEnd={({ zoom: z, coordinates }) => {
                setZoom(z);
                setCenter(coordinates);
              }}
              minZoom={1}
              maxZoom={10}
            >
              <Geographies geography={GEO_URL}>
                {({ geographies }) =>
                  geographies.map((geo) => (
                    <Geography
                      key={geo.rsmKey}
                      geography={geo}
                      style={{
                        default: { fill: '#1a1a2e', stroke: '#2d2d4a', strokeWidth: 0.4, outline: 'none' },
                        hover:   { fill: '#22223a', stroke: '#2d2d4a', strokeWidth: 0.4, outline: 'none' },
                        pressed: { fill: '#1a1a2e', stroke: '#2d2d4a', strokeWidth: 0.4, outline: 'none' },
                      }}
                    />
                  ))
                }
              </Geographies>

              {pontosOrdenados.map((ponto) => (
                <IpMarker
                  key={`${ponto.ip}`}
                  ponto={ponto}
                  onHover={handleHover}
                  onLeave={handleLeave}
                />
              ))}
            </ZoomableGroup>
          </ComposableMap>

          {/* Legenda sobreposta */}
          <MapLegend />

          {/* Tooltip de hover */}
          <HoverCard ponto={hoveredPonto} />

          {/* Botão de reset de zoom */}
          <Tooltip title="Resetar zoom" placement="left">
            <IconButton
              onClick={handleReset}
              size="small"
              sx={{
                position: 'absolute',
                top: 16,
                left: 16,
                backgroundColor: alpha('#0d0d1a', 0.9),
                border: '1px solid rgba(255,255,255,0.1)',
                color: 'text.secondary',
                '&:hover': { backgroundColor: alpha('#00d4ff', 0.1), color: 'primary.main' },
              }}
            >
              <MyLocationIcon fontSize="small" />
            </IconButton>
          </Tooltip>

          {pontos.length === 0 && (
            <Box sx={{
              position: 'absolute', inset: 0,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              flexDirection: 'column', gap: 1.5,
            }}>
              <PublicIcon sx={{ fontSize: 48, color: alpha('#fff', 0.1) }} />
              <Typography variant="body2" color="text.disabled">
                Nenhum IP com geolocalização encontrado. Realize uma análise primeiro.
              </Typography>
            </Box>
          )}
        </Paper>
      )}
    </Container>
  );
});

export default HeatMap;
