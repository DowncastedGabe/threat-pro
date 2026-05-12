import React, { useMemo, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Container,
  Grid,
  LinearProgress,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Typography,
  alpha,
} from '@mui/material';
import RouterIcon from '@mui/icons-material/Router';
import SecurityIcon from '@mui/icons-material/Security';
import ShieldIcon from '@mui/icons-material/Shield';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import SearchIcon from '@mui/icons-material/Search';
import { scanRouterHealth } from '../services/routerHealthService';

const riskColors = {
  low: 'success',
  medium: 'warning',
  high: 'error',
};

const riskLabels = {
  low: 'Baixo',
  medium: 'Medio',
  high: 'Alto',
};

function statusChip(status) {
  if (status === 'open') return { color: 'warning', label: 'Aberta' };
  if (status === 'closed_or_filtered') return { color: 'success', label: 'Fechada/Filtrada' };
  return { color: 'default', label: 'Inconclusivo' };
}

export default function RouterProtection() {
  const [target, setTarget] = useState('');
  const [timeoutSeconds, setTimeoutSeconds] = useState(1.5);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const riskColor = useMemo(() => {
    const level = result?.summary?.risk_level || 'low';
    if (level === 'high') return '#ff3b5c';
    if (level === 'medium') return '#ffb830';
    return '#00ff9d';
  }, [result]);

  const handleSubmit = async (event) => {
    event?.preventDefault();
    setLoading(true);
    setError('');
    setResult(null);

    try {
      const payload = {
        target: target.trim() || null,
        timeout_seconds: Number(timeoutSeconds) || 1.5,
      };
      const data = await scanRouterHealth(payload);
      setResult(data);
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Falha ao verificar o roteador.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Container maxWidth="lg" sx={{ py: 5, px: { xs: 2, sm: 3 } }}>
      <Box sx={{ textAlign: 'center', mb: 5 }}>
        <Box
          sx={{
            width: 64,
            height: 64,
            borderRadius: '18px',
            mx: 'auto',
            mb: 2.5,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            background: 'linear-gradient(135deg, rgba(0,212,255,0.2), rgba(0,255,157,0.08))',
            border: '1px solid rgba(0,212,255,0.3)',
          }}
        >
          <RouterIcon sx={{ color: 'primary.main', fontSize: 34 }} />
        </Box>
        <Typography variant="h4" gutterBottom sx={{ fontWeight: 800 }}>
          Protecao do Roteador
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ maxWidth: 620, mx: 'auto' }}>
          Verifique portas administrativas comuns do gateway local com conexoes curtas e seguras.
        </Typography>
      </Box>

      <Card sx={{ mb: 3 }}>
        <CardContent sx={{ p: 3 }}>
          <Box component="form" onSubmit={handleSubmit}>
            <Grid container spacing={2} alignItems="center">
              <Grid item xs={12} md={7}>
                <TextField
                  fullWidth
                  label="IP privado do roteador"
                  placeholder="Deixe vazio para detectar o gateway"
                  value={target}
                  onChange={(event) => setTarget(event.target.value)}
                  disabled={loading}
                  helperText="A API bloqueia alvos publicos para evitar uso indevido."
                />
              </Grid>
              <Grid item xs={12} md={2}>
                <TextField
                  fullWidth
                  type="number"
                  label="Timeout"
                  value={timeoutSeconds}
                  onChange={(event) => setTimeoutSeconds(event.target.value)}
                  disabled={loading}
                  inputProps={{ min: 0.2, max: 3, step: 0.1 }}
                />
              </Grid>
              <Grid item xs={12} md={3}>
                <Button
                  fullWidth
                  variant="contained"
                  type="submit"
                  disabled={loading}
                  startIcon={loading ? <CircularProgress size={18} color="inherit" /> : <SearchIcon />}
                  sx={{ height: 56 }}
                >
                  {loading ? 'Verificando...' : 'Verificar'}
                </Button>
              </Grid>
            </Grid>
          </Box>
        </CardContent>
      </Card>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {result && (
        <Stack spacing={3}>
          <Grid container spacing={3}>
            <Grid item xs={12} md={4}>
              <Card
                sx={{
                  height: '100%',
                  background: `radial-gradient(ellipse at top left, ${alpha(riskColor, 0.12)} 0%, transparent 68%)`,
                  borderColor: alpha(riskColor, 0.32),
                }}
              >
                <CardContent sx={{ p: 3 }}>
                  <Stack direction="row" spacing={1.5} alignItems="center" sx={{ mb: 2 }}>
                    <ShieldIcon sx={{ color: riskColor }} />
                    <Typography variant="h6">Risco do Gateway</Typography>
                  </Stack>
                  <Typography variant="h2" sx={{ color: riskColor, fontWeight: 900, lineHeight: 1 }}>
                    {result.summary.risk_score}
                  </Typography>
                  <LinearProgress
                    variant="determinate"
                    value={result.summary.risk_score}
                    color={riskColors[result.summary.risk_level] || 'success'}
                    sx={{ height: 8, borderRadius: 4, my: 2 }}
                  />
                  <Chip
                    label={riskLabels[result.summary.risk_level] || 'Baixo'}
                    color={riskColors[result.summary.risk_level] || 'success'}
                    sx={{ fontWeight: 800 }}
                  />
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} md={8}>
              <Card sx={{ height: '100%' }}>
                <CardContent sx={{ p: 3 }}>
                  <Stack direction="row" spacing={1.5} alignItems="center" sx={{ mb: 2 }}>
                    <SecurityIcon sx={{ color: 'primary.main' }} />
                    <Typography variant="h6">Resumo tecnico</Typography>
                  </Stack>
                  <Grid container spacing={2}>
                    <Grid item xs={12} sm={4}>
                      <Typography variant="caption" color="text.secondary">Gateway</Typography>
                      <Typography sx={{ fontFamily: '"JetBrains Mono", monospace', fontWeight: 700 }}>
                        {result.target}
                      </Typography>
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <Typography variant="caption" color="text.secondary">Portas abertas</Typography>
                      <Typography sx={{ fontWeight: 800 }}>
                        {result.summary.open_ports} / {result.summary.checked_ports}
                      </Typography>
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <Typography variant="caption" color="text.secondary">Origem</Typography>
                      <Typography sx={{ fontWeight: 700 }}>
                        {result.detected_gateway ? 'Gateway detectado' : 'Alvo informado'}
                      </Typography>
                    </Grid>
                    <Grid item xs={12}>
                      <Alert severity="info" sx={{ mt: 1 }}>
                        {result.scan_policy}
                      </Alert>
                    </Grid>
                  </Grid>
                </CardContent>
              </Card>
            </Grid>
          </Grid>

          <Card>
            <CardContent sx={{ p: 3 }}>
              <Typography variant="h6" sx={{ mb: 2 }}>Portas verificadas</Typography>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Porta</TableCell>
                      <TableCell>Servico</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell>Latencia</TableCell>
                      <TableCell>Risco</TableCell>
                      <TableCell>Recomendacao</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {result.ports.map((port) => {
                      const chip = statusChip(port.status);
                      return (
                        <TableRow key={port.port} hover>
                          <TableCell sx={{ fontFamily: '"JetBrains Mono", monospace', fontWeight: 800 }}>
                            {port.port}
                          </TableCell>
                          <TableCell>{port.service}</TableCell>
                          <TableCell>
                            <Chip size="small" color={chip.color} label={chip.label} sx={{ fontWeight: 700 }} />
                          </TableCell>
                          <TableCell>{port.latency_ms ? `${port.latency_ms} ms` : '-'}</TableCell>
                          <TableCell>
                            <Chip
                              size="small"
                              color={riskColors[port.risk] || 'default'}
                              label={riskLabels[port.risk] || 'Baixo'}
                              variant="outlined"
                            />
                          </TableCell>
                          <TableCell sx={{ color: 'text.secondary' }}>{port.recommendation}</TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </TableContainer>
            </CardContent>
          </Card>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Card sx={{ height: '100%' }}>
                <CardContent sx={{ p: 3 }}>
                  <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 2 }}>
                    <WarningAmberIcon sx={{ color: 'warning.main' }} />
                    <Typography variant="h6">Achados</Typography>
                  </Stack>
                  <Stack spacing={1}>
                    {result.findings.map((finding) => (
                      <Alert key={finding} severity="warning" variant="outlined">{finding}</Alert>
                    ))}
                  </Stack>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} md={6}>
              <Card sx={{ height: '100%' }}>
                <CardContent sx={{ p: 3 }}>
                  <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 2 }}>
                    <CheckCircleIcon sx={{ color: 'success.main' }} />
                    <Typography variant="h6">Recomendacoes</Typography>
                  </Stack>
                  <Stack spacing={1}>
                    {result.recommendations.map((item) => (
                      <Alert key={item} severity="success" variant="outlined">{item}</Alert>
                    ))}
                  </Stack>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        </Stack>
      )}
    </Container>
  );
}
