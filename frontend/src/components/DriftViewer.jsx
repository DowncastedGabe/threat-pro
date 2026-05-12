/**
 * DriftViewer.jsx — Visualização de Diff de Portas (Drift Analysis)
 *
 * Semântica de cores:
 *   Verde  (success) → porta nova aberta (pode ser legítima ou nova exposição)
 *   Vermelho (error) → porta fechada (serviço removido ou filtrado)
 *   Laranja (warning) → versão/produto mudou (risco de atualização ou downgrade)
 */

import React, { useMemo } from 'react';
import {
  Box, Typography, Chip, Stack, alpha, Collapse,
  Table, TableBody, TableCell, TableHead, TableRow,
} from '@mui/material';
import AddCircleOutlineIcon  from '@mui/icons-material/AddCircleOutline';
import RemoveCircleOutlineIcon from '@mui/icons-material/RemoveCircleOutline';
import SwapHorizIcon          from '@mui/icons-material/SwapHoriz';
import CheckCircleOutlineIcon from '@mui/icons-material/CheckCircleOutline';

/* ── Configuração de cada tipo de evento ─────────────────────────────────── */
const DRIFT_TIPOS = {
  novas: {
    icon:  <AddCircleOutlineIcon sx={{ fontSize: 16 }} />,
    label: 'Portas Novas',
    color: '#ff3b5c',  // vermelho — nova exposição = risco aumentado
    muiColor: 'error',
    descricao: 'Portas que estavam fechadas e agora estão abertas.',
  },
  fechadas: {
    icon:  <RemoveCircleOutlineIcon sx={{ fontSize: 16 }} />,
    label: 'Portas Fechadas',
    color: '#00ff9d',  // verde — redução de superfície de ataque
    muiColor: 'success',
    descricao: 'Portas que estavam abertas e agora foram fechadas.',
  },
  versoes_mudaram: {
    icon:  <SwapHorizIcon sx={{ fontSize: 16 }} />,
    label: 'Versões Alteradas',
    color: '#ffb830',  // laranja — mudança de versão requer investigação
    muiColor: 'warning',
    descricao: 'Portas cujo serviço ou versão foi alterado.',
  },
};

/* ── Sub-componentes ─────────────────────────────────────────────────────── */

function PortaRow({ porta, tipo }) {
  const cfg = DRIFT_TIPOS[tipo];
  return (
    <TableRow
      sx={{
        '&:last-child td': { borderBottom: 0 },
        backgroundColor: alpha(cfg.color, 0.03),
        '&:hover': { backgroundColor: alpha(cfg.color, 0.06) },
      }}
    >
      <TableCell sx={{ py: 1 }}>
        <Chip
          label={porta.porta || porta.depois?.porta || '?'}
          size="small"
          sx={{
            fontFamily: '"JetBrains Mono", monospace',
            fontWeight: 700,
            fontSize: '0.75rem',
            backgroundColor: alpha(cfg.color, 0.12),
            color: cfg.color,
          }}
        />
      </TableCell>
      <TableCell sx={{ py: 1 }}>
        <Typography variant="caption" color="text.secondary" sx={{ fontFamily: '"JetBrains Mono", monospace' }}>
          {porta.protocolo || porta.depois?.protocolo || 'tcp'}
        </Typography>
      </TableCell>
      <TableCell sx={{ py: 1 }}>
        <Typography variant="caption" color="text.secondary">
          {porta.servico || porta.depois?.servico || '—'}
        </Typography>
      </TableCell>
      <TableCell sx={{ py: 1 }}>
        {tipo === 'versoes_mudaram' ? (
          <Stack direction="row" spacing={0.5} alignItems="center" flexWrap="wrap">
            <Typography variant="caption" sx={{ color: '#ff6b6b', fontFamily: '"JetBrains Mono", monospace', fontSize: '0.72rem' }}>
              {porta.antes?.produto || '—'} {porta.antes?.versao || ''}
            </Typography>
            <SwapHorizIcon sx={{ fontSize: 14, color: 'text.disabled' }} />
            <Typography variant="caption" sx={{ color: '#00ff9d', fontFamily: '"JetBrains Mono", monospace', fontSize: '0.72rem' }}>
              {porta.depois?.produto || '—'} {porta.depois?.versao || ''}
            </Typography>
          </Stack>
        ) : (
          <Typography variant="caption" sx={{ fontFamily: '"JetBrains Mono", monospace', fontSize: '0.72rem', color: 'text.secondary' }}>
            {porta.produto || '—'} {porta.versao || ''}
          </Typography>
        )}
      </TableCell>
    </TableRow>
  );
}

function DriftSection({ tipo, itens }) {
  const cfg   = DRIFT_TIPOS[tipo];
  const count = itens.length;

  if (count === 0) return null;

  return (
    <Box
      sx={{
        borderRadius: 2,
        border: `1px solid ${alpha(cfg.color, 0.2)}`,
        overflow: 'hidden',
        mb: 1.5,
      }}
    >
      {/* Header da seção */}
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          gap: 1.5,
          px: 2,
          py: 1.2,
          backgroundColor: alpha(cfg.color, 0.06),
          borderBottom: `1px solid ${alpha(cfg.color, 0.12)}`,
        }}
      >
        <Box sx={{ color: cfg.color, display: 'flex' }}>{cfg.icon}</Box>
        <Typography variant="body2" sx={{ fontWeight: 700, color: cfg.color }}>
          {cfg.label}
        </Typography>
        <Chip
          label={count}
          size="small"
          color={cfg.muiColor}
          sx={{ fontWeight: 800, height: 20, fontSize: '0.68rem', ml: 'auto' }}
        />
      </Box>

      {/* Tabela de portas */}
      <Box sx={{ overflowX: 'auto' }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              {['Porta', 'Protocolo', 'Serviço', 'Produto / Versão'].map((h) => (
                <TableCell
                  key={h}
                  sx={{ py: 0.8, fontSize: '0.7rem', color: 'text.disabled', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}
                >
                  {h}
                </TableCell>
              ))}
            </TableRow>
          </TableHead>
          <TableBody>
            {itens.map((item, i) => (
              <PortaRow key={i} porta={item} tipo={tipo} />
            ))}
          </TableBody>
        </Table>
      </Box>

      {/* Dica semântica */}
      <Box sx={{ px: 2, py: 1, backgroundColor: alpha(cfg.color, 0.03) }}>
        <Typography variant="caption" color="text.disabled" sx={{ fontSize: '0.7rem' }}>
          {cfg.descricao}
        </Typography>
      </Box>
    </Box>
  );
}

/* ── Componente principal ────────────────────────────────────────────────── */
export default function DriftViewer({ drift }) {
  const totalMudancas = useMemo(() => {
    if (!drift) return 0;
    return (drift.novas?.length || 0) + (drift.fechadas?.length || 0) + (drift.versoes_mudaram?.length || 0);
  }, [drift]);

  if (!drift || !drift.tem_mudancas) {
    return (
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          gap: 1.5,
          p: 2,
          borderRadius: 2,
          backgroundColor: alpha('#00ff9d', 0.04),
          border: '1px solid rgba(0,255,157,0.1)',
        }}
      >
        <CheckCircleOutlineIcon sx={{ color: '#00ff9d', fontSize: 20 }} />
        <Typography variant="body2" color="text.secondary">
          {drift ? 'Nenhuma mudança detectada em relação ao scan anterior.' : 'Primeiro scan deste IP — sem histórico para comparar.'}
        </Typography>
      </Box>
    );
  }

  return (
    <Box>
      {/* Badge de resumo */}
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
        <Typography variant="subtitle2" sx={{ fontWeight: 700, color: '#ffb830' }}>
          ⚠ {totalMudancas} mudança{totalMudancas !== 1 ? 's' : ''} detectada{totalMudancas !== 1 ? 's' : ''}
        </Typography>
        {drift.novas?.length > 0 && (
          <Chip label={`+${drift.novas.length} novas`} size="small" color="error" sx={{ fontSize: '0.68rem', fontWeight: 700 }} />
        )}
        {drift.fechadas?.length > 0 && (
          <Chip label={`-${drift.fechadas.length} fechadas`} size="small" color="success" sx={{ fontSize: '0.68rem', fontWeight: 700 }} />
        )}
        {drift.versoes_mudaram?.length > 0 && (
          <Chip label={`${drift.versoes_mudaram.length} versões`} size="small" color="warning" sx={{ fontSize: '0.68rem', fontWeight: 700 }} />
        )}
      </Box>

      <DriftSection tipo="novas"          itens={drift.novas          || []} />
      <DriftSection tipo="versoes_mudaram" itens={drift.versoes_mudaram || []} />
      <DriftSection tipo="fechadas"       itens={drift.fechadas       || []} />
    </Box>
  );
}
