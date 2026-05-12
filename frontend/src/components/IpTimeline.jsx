/**
 * IpTimeline.jsx — Timeline de eventos históricos de um IP
 *
 * Usa @mui/lab/Timeline para renderizar uma linha do tempo cronológica.
 * Cada evento é colorido semanticamente:
 *   - scan_manual   → azul (primary)
 *   - scan_agendado → ciano (secondary)
 *   - drift         → laranja/vermelho com alerta
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
  Box, Typography, Chip, CircularProgress, Alert, alpha, Stack,
} from '@mui/material';
import Timeline from '@mui/lab/Timeline';
import TimelineItem from '@mui/lab/TimelineItem';
import TimelineSeparator from '@mui/lab/TimelineSeparator';
import TimelineConnector from '@mui/lab/TimelineConnector';
import TimelineContent from '@mui/lab/TimelineContent';
import TimelineDot from '@mui/lab/TimelineDot';
import TimelineOppositeContent from '@mui/lab/TimelineOppositeContent';
import NetworkCheckIcon   from '@mui/icons-material/NetworkCheck';
import ScheduleIcon       from '@mui/icons-material/Schedule';
import WarningAmberIcon   from '@mui/icons-material/WarningAmber';
import { format, parseISO } from 'date-fns';
import { ptBR } from 'date-fns/locale';
import api from '../api';

/* ── Configuração por tipo de evento ─────────────────────────────────────── */
const EVENTO_CONFIG = {
  scan_manual:   { icon: <NetworkCheckIcon sx={{ fontSize: 16 }} />, color: 'primary',   label: 'Manual',   hex: '#00d4ff' },
  scan_agendado: { icon: <ScheduleIcon     sx={{ fontSize: 16 }} />, color: 'secondary',  label: 'Agendado', hex: '#00ff9d' },
  drift:         { icon: <WarningAmberIcon sx={{ fontSize: 16 }} />, color: 'warning',    label: 'Drift',    hex: '#ffb830' },
};

function fmtData(iso) {
  try {
    return format(parseISO(iso), "dd/MM HH:mm", { locale: ptBR });
  } catch {
    return iso ?? '—';
  }
}

/* ── Item individual da timeline ─────────────────────────────────────────── */
function EventoItem({ evento, ultimo }) {
  const cfg = EVENTO_CONFIG[evento.tipo] || EVENTO_CONFIG.scan_manual;
  const temAlerta = evento.tem_alerta;

  return (
    <TimelineItem>
      <TimelineOppositeContent
        sx={{ flex: 0.3, pt: '10px', pr: 1 }}
        align="right"
      >
        <Typography
          variant="caption"
          sx={{
            fontFamily: '"JetBrains Mono", monospace',
            color: 'text.disabled',
            fontSize: '0.7rem',
          }}
        >
          {fmtData(evento.timestamp)}
        </Typography>
      </TimelineOppositeContent>

      <TimelineSeparator>
        <TimelineDot
          color={temAlerta ? 'warning' : cfg.color}
          variant={temAlerta ? 'filled' : 'outlined'}
          sx={{
            p: 0.6,
            boxShadow: temAlerta ? `0 0 10px ${alpha(cfg.hex, 0.5)}` : 'none',
          }}
        >
          {cfg.icon}
        </TimelineDot>
        {!ultimo && <TimelineConnector sx={{ backgroundColor: 'rgba(255,255,255,0.06)' }} />}
      </TimelineSeparator>

      <TimelineContent sx={{ pt: '6px', pb: ultimo ? 0 : 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.8, mb: 0.3 }}>
          <Chip
            label={cfg.label}
            size="small"
            sx={{
              height: 18,
              fontSize: '0.62rem',
              fontWeight: 700,
              backgroundColor: alpha(cfg.hex, 0.12),
              color: cfg.hex,
            }}
          />
          {temAlerta && (
            <Chip
              label="ALERTA"
              size="small"
              color="warning"
              sx={{ height: 18, fontSize: '0.62rem', fontWeight: 800 }}
            />
          )}
        </Box>
        <Typography
          variant="caption"
          color={temAlerta ? 'warning.light' : 'text.secondary'}
          sx={{ lineHeight: 1.5, display: 'block', fontSize: '0.76rem' }}
        >
          {evento.descricao}
        </Typography>
      </TimelineContent>
    </TimelineItem>
  );
}

/* ── Componente principal ────────────────────────────────────────────────── */
export default function IpTimeline({ ip }) {
  const [eventos, setEventos] = useState([]);
  const [loading, setLoading] = useState(false);
  const [erro, setErro]       = useState('');

  const carregarTimeline = useCallback(async () => {
    if (!ip) return;
    setLoading(true);
    setErro('');
    try {
      const res = await api.get(`/historico/${ip}/timeline`);
      // API retorna em ordem ascendente — invertemos para mostrar mais recente no topo
      setEventos([...(res.data || [])].reverse());
    } catch (err) {
      setErro(err.response?.data?.detail || 'Erro ao carregar timeline.');
    } finally {
      setLoading(false);
    }
  }, [ip]);

  useEffect(() => { carregarTimeline(); }, [carregarTimeline]);

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
        <CircularProgress size={28} />
      </Box>
    );
  }

  if (erro) {
    return <Alert severity="error" sx={{ borderRadius: 2, fontSize: '0.8rem' }}>{erro}</Alert>;
  }

  if (eventos.length === 0) {
    return (
      <Box sx={{ textAlign: 'center', py: 3 }}>
        <NetworkCheckIcon sx={{ fontSize: 40, color: alpha('#fff', 0.08), mb: 1 }} />
        <Typography variant="body2" color="text.disabled">
          Nenhum evento registrado para este IP.
        </Typography>
      </Box>
    );
  }

  return (
    <Box>
      {/* Legenda */}
      <Stack direction="row" spacing={1} sx={{ mb: 2, flexWrap: 'wrap', gap: 0.5 }}>
        {Object.entries(EVENTO_CONFIG).map(([tipo, cfg]) => (
          <Chip
            key={tipo}
            icon={cfg.icon}
            label={cfg.label}
            size="small"
            sx={{
              height: 22,
              fontSize: '0.68rem',
              backgroundColor: alpha(cfg.hex, 0.08),
              color: cfg.hex,
              '& .MuiChip-icon': { color: cfg.hex, fontSize: '14px !important' },
            }}
          />
        ))}
        <Typography variant="caption" color="text.disabled" sx={{ ml: 'auto', alignSelf: 'center' }}>
          {eventos.length} evento{eventos.length !== 1 ? 's' : ''}
        </Typography>
      </Stack>

      <Timeline sx={{ p: 0, m: 0, '& .MuiTimelineItem-root:before': { display: 'none' } }}
        // Remove o padding padrão que o MUI coloca no lado esquerdo
        // mas mantemos o TimelineOppositeContent para as datas
      >
        {eventos.map((evento, idx) => (
          <EventoItem
            key={`${evento.tipo}-${evento.timestamp}`}
            evento={evento}
            ultimo={idx === eventos.length - 1}
          />
        ))}
      </Timeline>
    </Box>
  );
}
