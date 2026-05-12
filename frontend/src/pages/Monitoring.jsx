/**
 * Monitoring.jsx — Gerenciamento de Escaneamentos Periódicos Agendados
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
  Box, Container, Typography, TextField, Button, CircularProgress,
  Card, CardContent, Table, TableBody, TableCell, TableHead, TableRow,
  Chip, Stack, Alert, Snackbar, alpha, IconButton, Tooltip, Skeleton,
  Dialog, DialogTitle, DialogContent, DialogActions,
} from '@mui/material';
import ScheduleIcon     from '@mui/icons-material/Schedule';
import DeleteOutlineIcon from '@mui/icons-material/DeleteOutline';
import AddAlertIcon     from '@mui/icons-material/AddAlert';
import RefreshIcon      from '@mui/icons-material/Refresh';
import AccessTimeIcon   from '@mui/icons-material/AccessTime';
import api from '../api';

/* ── Helpers ──────────────────────────────────────────────────────────────── */

function formatarData(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString('pt-BR', {
    dateStyle: 'short',
    timeStyle: 'short',
  });
}

function FrequenciaChip({ horas }) {
  const label = horas === 1     ? '1 hora'
              : horas < 24      ? `${horas}h`
              : horas === 24    ? 'Diário'
              : horas === 168   ? 'Semanal'
              : horas === 720   ? 'Mensal'
              : `${horas}h`;

  return (
    <Chip
      icon={<AccessTimeIcon sx={{ fontSize: '0.85rem !important' }} />}
      label={label}
      size="small"
      variant="outlined"
      sx={{ fontWeight: 600, fontSize: '0.72rem', borderColor: 'rgba(0,212,255,0.3)', color: 'primary.light' }}
    />
  );
}

/* ── Formulário de cadastro ──────────────────────────────────────────────── */
function CadastroForm({ onSuccess }) {
  const [ip, setIp]         = useState('');
  const [horas, setHoras]   = useState(24);
  const [loading, setLoading] = useState(false);
  const [erro, setErro]     = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!ip.trim()) return;
    setLoading(true);
    setErro('');
    try {
      await api.post('/monitorar/', { ip: ip.trim(), frequencia_horas: Number(horas) });
      setIp('');
      setHoras(24);
      onSuccess('Monitoramento agendado com sucesso!');
    } catch (err) {
      setErro(err.response?.data?.detail || err.message || 'Erro ao criar agendamento.');
    } finally {
      setLoading(false);
    }
  };

  const FREQUENCIAS_PRESET = [
    { label: '1h',      value: 1 },
    { label: '6h',      value: 6 },
    { label: '12h',     value: 12 },
    { label: 'Diário',  value: 24 },
    { label: 'Semanal', value: 168 },
  ];

  return (
    <Card
      elevation={0}
      sx={{
        mb: 4,
        border: '1px solid rgba(0,212,255,0.12)',
        background: 'linear-gradient(135deg, rgba(0,212,255,0.03), rgba(0,255,157,0.02))',
      }}
    >
      <CardContent sx={{ p: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 3 }}>
          <AddAlertIcon sx={{ color: 'primary.main' }} />
          <Typography variant="h6" sx={{ fontWeight: 700 }}>Novo Agendamento</Typography>
        </Box>

        <Box component="form" onSubmit={handleSubmit}>
          <Stack spacing={2.5}>
            <TextField
              label="Endereço IP"
              placeholder="ex: 8.8.8.8"
              value={ip}
              onChange={(e) => setIp(e.target.value)}
              disabled={loading}
              fullWidth
              inputProps={{ style: { fontFamily: '"JetBrains Mono", monospace' } }}
              helperText="Apenas IPs públicos são permitidos."
            />

            <Box>
              <Typography variant="caption" color="text.secondary" sx={{ mb: 1, display: 'block' }}>
                Frequência de escaneamento
              </Typography>
              <Stack direction="row" spacing={1} flexWrap="wrap" sx={{ mb: 1.5, gap: 1 }}>
                {FREQUENCIAS_PRESET.map((p) => (
                  <Chip
                    key={p.value}
                    label={p.label}
                    onClick={() => setHoras(p.value)}
                    variant={horas === p.value ? 'filled' : 'outlined'}
                    color={horas === p.value ? 'primary' : 'default'}
                    sx={{ fontWeight: 600, cursor: 'pointer' }}
                  />
                ))}
              </Stack>
              <TextField
                label="Personalizado (horas)"
                type="number"
                value={horas}
                onChange={(e) => setHoras(Math.max(1, Math.min(8760, Number(e.target.value))))}
                inputProps={{ min: 1, max: 8760 }}
                size="small"
                sx={{ width: 200 }}
                helperText="Mín: 1h · Máx: 8760h (1 ano)"
              />
            </Box>

            {erro && <Alert severity="error" sx={{ borderRadius: 2 }}>{erro}</Alert>}

            <Button
              type="submit"
              variant="contained"
              color="primary"
              disabled={loading || !ip.trim()}
              startIcon={loading ? <CircularProgress size={16} color="inherit" /> : <ScheduleIcon />}
              sx={{ alignSelf: 'flex-start', minWidth: 180 }}
            >
              {loading ? 'Agendando…' : 'Agendar Scan'}
            </Button>
          </Stack>
        </Box>
      </CardContent>
    </Card>
  );
}

/* ── Tabela de agendamentos ───────────────────────────────────────────────── */
function TabelaAgendamentos({ agendamentos, loading, onRemover }) {
  if (loading) {
    return (
      <Stack spacing={1}>
        {[1, 2, 3].map((i) => <Skeleton key={i} variant="rectangular" height={56} sx={{ borderRadius: 1 }} />)}
      </Stack>
    );
  }

  if (agendamentos.length === 0) {
    return (
      <Box sx={{ textAlign: 'center', py: 8 }}>
        <ScheduleIcon sx={{ fontSize: 48, color: alpha('#fff', 0.08), mb: 2 }} />
        <Typography color="text.disabled">Nenhum agendamento cadastrado.</Typography>
        <Typography variant="caption" color="text.disabled">
          Adicione um IP acima para começar o monitoramento periódico.
        </Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ overflowX: 'auto' }}>
      <Table>
        <TableHead>
          <TableRow>
            {['IP', 'Frequência', 'Status', 'Último Scan', 'Criado em', 'Ações'].map((h) => (
              <TableCell
                key={h}
                sx={{
                  fontSize: '0.7rem', color: 'text.disabled', fontWeight: 700,
                  textTransform: 'uppercase', letterSpacing: '0.08em',
                  borderBottom: '1px solid rgba(255,255,255,0.06)',
                }}
              >
                {h}
              </TableCell>
            ))}
          </TableRow>
        </TableHead>
        <TableBody>
          {agendamentos.map((ag) => (
            <TableRow
              key={ag.id}
              sx={{
                '&:last-child td': { borderBottom: 0 },
                '&:hover td': { backgroundColor: alpha('#fff', 0.02) },
              }}
            >
              <TableCell>
                <Typography
                  variant="body2"
                  sx={{ fontFamily: '"JetBrains Mono", monospace', fontWeight: 700, color: 'primary.light' }}
                >
                  {ag.ip}
                </Typography>
              </TableCell>
              <TableCell><FrequenciaChip horas={ag.frequencia_horas} /></TableCell>
              <TableCell>
                <Chip
                  label={ag.ativo ? 'Ativo' : 'Inativo'}
                  size="small"
                  color={ag.ativo ? 'success' : 'default'}
                  sx={{ fontWeight: 700, fontSize: '0.68rem' }}
                />
              </TableCell>
              <TableCell>
                <Typography variant="caption" color="text.secondary">
                  {formatarData(ag.ultimo_scan)}
                </Typography>
              </TableCell>
              <TableCell>
                <Typography variant="caption" color="text.secondary">
                  {formatarData(ag.criado_em)}
                </Typography>
              </TableCell>
              <TableCell>
                <Tooltip title="Remover agendamento">
                  <IconButton
                    size="small"
                    onClick={() => onRemover(ag)}
                    sx={{
                      color: 'text.disabled',
                      '&:hover': { color: '#ff3b5c', backgroundColor: alpha('#ff3b5c', 0.08) },
                    }}
                  >
                    <DeleteOutlineIcon fontSize="small" />
                  </IconButton>
                </Tooltip>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </Box>
  );
}

/* ── Página principal ────────────────────────────────────────────────────── */
export default function Monitoring() {
  const [agendamentos, setAgendamentos] = useState([]);
  const [loading, setLoading]           = useState(true);
  const [snackbar, setSnackbar]         = useState({ open: false, msg: '', severity: 'success' });
  const [confirmar, setConfirmar]       = useState(null); // agendamento a remover

  const carregarAgendamentos = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.get('/monitorar/');
      setAgendamentos(res.data);
    } catch {
      setSnackbar({ open: true, msg: 'Erro ao carregar agendamentos.', severity: 'error' });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { carregarAgendamentos(); }, [carregarAgendamentos]);

  const handleSuccess = useCallback((msg) => {
    setSnackbar({ open: true, msg, severity: 'success' });
    carregarAgendamentos();
  }, [carregarAgendamentos]);

  const handleRemoverConfirmado = async () => {
    if (!confirmar) return;
    try {
      await api.delete(`/monitorar/${confirmar.id}`);
      setConfirmar(null);
      handleSuccess(`Monitoramento para ${confirmar.ip} removido.`);
    } catch (err) {
      setSnackbar({ open: true, msg: err.response?.data?.detail || 'Erro ao remover.', severity: 'error' });
    }
  };

  return (
    <Container maxWidth="lg" sx={{ py: 5, px: { xs: 2, sm: 3 } }}>
      {/* Hero */}
      <Box sx={{ textAlign: 'center', mb: 5 }}>
        <Box sx={{
          display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
          width: 64, height: 64, borderRadius: '18px', mb: 2.5,
          background: 'linear-gradient(135deg, rgba(0,255,157,0.15), rgba(0,212,255,0.05))',
          border: '1px solid rgba(0,255,157,0.3)',
        }}>
          <ScheduleIcon sx={{ color: 'secondary.main', fontSize: 32 }} />
        </Box>
        <Typography variant="h4" gutterBottom sx={{ fontWeight: 800 }}>
          Monitoramento Periódico
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ maxWidth: 520, mx: 'auto' }}>
          Agende scans automáticos de Nmap para IPs de interesse. O servidor executará
          os scans na frequência definida e calculará o drift automaticamente.
        </Typography>
      </Box>

      {/* Formulário de cadastro */}
      <CadastroForm onSuccess={handleSuccess} />

      {/* Lista de agendamentos */}
      <Card
        elevation={0}
        sx={{ border: '1px solid rgba(255,255,255,0.06)' }}
      >
        <CardContent sx={{ p: 0 }}>
          <Box sx={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            px: 3, py: 2, borderBottom: '1px solid rgba(255,255,255,0.06)',
          }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                Agendamentos Ativos
              </Typography>
              <Chip
                label={agendamentos.length}
                size="small"
                color="primary"
                sx={{ fontWeight: 800, height: 20 }}
              />
            </Box>
            <Tooltip title="Atualizar lista">
              <IconButton size="small" onClick={carregarAgendamentos} disabled={loading}
                sx={{ color: 'text.secondary', '&:hover': { color: 'primary.main' } }}>
                <RefreshIcon fontSize="small" />
              </IconButton>
            </Tooltip>
          </Box>

          <TabelaAgendamentos
            agendamentos={agendamentos}
            loading={loading}
            onRemover={setConfirmar}
          />
        </CardContent>
      </Card>

      {/* Dialog de confirmação de remoção */}
      <Dialog
        open={!!confirmar}
        onClose={() => setConfirmar(null)}
        PaperProps={{ sx: { borderRadius: 3, border: '1px solid rgba(255,59,92,0.2)', backgroundColor: '#0d0d1a' } }}
      >
        <DialogTitle sx={{ fontWeight: 700 }}>Remover Agendamento</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary">
            Tem certeza que deseja remover o monitoramento para{' '}
            <Typography component="span" sx={{ fontFamily: '"JetBrains Mono", monospace', color: '#ff3b5c', fontWeight: 700 }}>
              {confirmar?.ip}
            </Typography>
            ? O job será cancelado imediatamente.
          </Typography>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2, gap: 1 }}>
          <Button onClick={() => setConfirmar(null)} variant="outlined" color="inherit" size="small">
            Cancelar
          </Button>
          <Button onClick={handleRemoverConfirmado} variant="contained" color="error" size="small">
            Remover
          </Button>
        </DialogActions>
      </Dialog>

      {/* Snackbar */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={5000}
        onClose={() => setSnackbar((s) => ({ ...s, open: false }))}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert
          severity={snackbar.severity}
          variant="filled"
          onClose={() => setSnackbar((s) => ({ ...s, open: false }))}
          sx={{ fontWeight: 600, borderRadius: 2 }}
        >
          {snackbar.msg}
        </Alert>
      </Snackbar>
    </Container>
  );
}
