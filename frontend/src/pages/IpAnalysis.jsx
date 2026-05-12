import React, { useState } from 'react';
import {
  Box, Container, Typography, TextField, Button, CircularProgress,
  Card, CardContent, Grid, LinearProgress, Table, TableBody,
  TableCell, TableContainer, TableHead, TableRow, Paper,
  Snackbar, Alert, Chip, Stack, Skeleton, alpha,
  Accordion, AccordionSummary, AccordionDetails,
} from '@mui/material';
import SearchIcon from '@mui/icons-material/Search';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import GppBadIcon from '@mui/icons-material/GppBad';
import RouterIcon from '@mui/icons-material/Router';
import SecurityIcon from '@mui/icons-material/Security';
import PublicIcon from '@mui/icons-material/Public';
import CompareArrowsIcon from '@mui/icons-material/CompareArrows';
import BugReportIcon from '@mui/icons-material/BugReport';
import api from '../api';
import DriftViewer from '../components/DriftViewer';
import CveList from '../components/CveList';

/* ── Risk helpers ─────────────────────────────────────────── */
const RISK_MUI = { critico: 'error', alto: 'warning', medio: 'info', baixo: 'success', desconhecido: 'default' };
const RISK_GLOW = { critico: '#ff3b5c', alto: '#ffb830', medio: '#00d4ff', baixo: '#00ff9d', desconhecido: '#8e8e93' };

function riskByScore(score) {
  if (score >= 75) return 'critico';
  if (score >= 50) return 'alto';
  if (score >= 25) return 'medio';
  return 'baixo';
}

/* ── Sub-components ──────────────────────────────────────── */
function RiskCard({ result }) {
  const risco = (result.resultado || riskByScore(result.score)).toLowerCase();
  const glow  = RISK_GLOW[risco] || '#8e8e93';

  return (
    <Card sx={{
      height: '100%',
      background: `radial-gradient(ellipse at top left, ${alpha(glow, 0.12)} 0%, transparent 70%)`,
      borderColor: alpha(glow, 0.3),
    }}>
      <CardContent sx={{ textAlign: 'center', py: 4, px: 3 }}>
        <Typography variant="caption" color="text.secondary" sx={{ mb: 2, display: 'block' }}>
          Score de Risco (AbuseIPDB)
        </Typography>
        <Box sx={{
          width: 120, height: 120, borderRadius: '50%', mx: 'auto', mb: 2,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          background: `radial-gradient(circle, ${alpha(glow, 0.15)}, transparent 70%)`,
          border: `3px solid ${alpha(glow, 0.4)}`,
          boxShadow: `0 0 32px ${alpha(glow, 0.3)}`,
        }}>
          <Typography variant="h2" sx={{ fontWeight: 900, color: glow, lineHeight: 1 }}>
            {result.score}
          </Typography>
        </Box>
        <LinearProgress
          variant="determinate"
          value={result.score}
          color={RISK_MUI[risco]}
          sx={{ height: 8, borderRadius: 4, mb: 2 }}
        />
        <Chip
          label={risco.toUpperCase()}
          color={RISK_MUI[risco]}
          sx={{ fontWeight: 800, px: 2, letterSpacing: '0.12em', boxShadow: `0 0 16px ${alpha(glow, 0.4)}` }}
        />
        <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
          {result.total_reports} relato(s) no AbuseIPDB
        </Typography>
      </CardContent>
    </Card>
  );
}

function DataRow({ label, value, mono = false }) {
  return (
    <Box sx={{ py: 1.5, borderBottom: '1px solid rgba(255,255,255,0.04)', '&:last-child': { border: 0 } }}>
      <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 0.3 }}>
        {label}
      </Typography>
      <Typography
        variant="body2"
        sx={{ fontWeight: 600, fontFamily: mono ? '"JetBrains Mono", monospace' : 'inherit', wordBreak: 'break-all' }}
      >
        {value || '—'}
      </Typography>
    </Box>
  );
}

function GeoCard({ result, ip }) {
  const geo = result.geoip || {};
  return (
    <Card sx={{ height: '100%' }}>
      <CardContent sx={{ p: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2.5 }}>
          <PublicIcon sx={{ color: 'primary.main', fontSize: 20 }} />
          <Typography variant="h6">GeoIP & Provedor</Typography>
        </Box>
        <Grid container spacing={0}>
          <Grid item xs={6}><DataRow label="IP Analisado"  value={geo.ip || ip} mono /></Grid>
          <Grid item xs={6}><DataRow label="País"          value={geo.pais} /></Grid>
          <Grid item xs={6}><DataRow label="Região"        value={geo.regiao} /></Grid>
          <Grid item xs={6}><DataRow label="Cidade"        value={geo.cidade} /></Grid>
          <Grid item xs={12}><DataRow label="ISP / Provedor"  value={geo.isp} /></Grid>
          <Grid item xs={12}><DataRow label="Organização"    value={geo.organizacao} /></Grid>
          <Grid item xs={6}><DataRow label="ASN"           value={geo.asn} mono /></Grid>
          <Grid item xs={6}><DataRow label="Fuso Horário"  value={geo.timezone} /></Grid>
        </Grid>
      </CardContent>
    </Card>
  );
}

function NmapSection({ portas }) {
  if (!portas || portas.length === 0) {
    return (
      <Box sx={{ p: 4, textAlign: 'center', backgroundColor: 'rgba(255,255,255,0.02)', borderRadius: 2, border: '1px dashed rgba(255,255,255,0.08)' }}>
        <Typography variant="body2" color="text.secondary">Nenhuma porta aberta encontrada no escaneamento.</Typography>
      </Box>
    );
  }
  return (
    <TableContainer component={Paper} elevation={0} sx={{ backgroundColor: 'transparent', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 2 }}>
      <Table size="small">
        <TableHead>
          <TableRow sx={{ backgroundColor: 'rgba(0,212,255,0.04)' }}>
            {['Porta', 'Estado', 'Serviço', 'Produto / Versão'].map(h => (
              <TableCell key={h}>{h}</TableCell>
            ))}
          </TableRow>
        </TableHead>
        <TableBody>
          {portas.map((row, i) => (
            <TableRow key={i} hover>
              <TableCell>
                <Typography sx={{ fontFamily: '"JetBrains Mono", monospace', fontWeight: 700, color: 'primary.main', fontSize: '0.85rem' }}>
                  {row.porta ?? row.port}
                </Typography>
              </TableCell>
              <TableCell>
                <Chip
                  label={(row.estado ?? row.state ?? '—').toUpperCase()}
                  size="small"
                  color={(row.estado ?? row.state) === 'open' ? 'success' : 'default'}
                  sx={{ fontWeight: 700, fontSize: '0.68rem' }}
                />
              </TableCell>
              <TableCell sx={{ color: 'text.secondary', fontSize: '0.85rem' }}>{row.servico ?? row.name ?? '—'}</TableCell>
              <TableCell sx={{ color: 'text.secondary', fontSize: '0.8rem' }}>
                {[row.produto ?? row.product, row.versao ?? row.version, row.extra ?? row.extrainfo].filter(Boolean).join(' ') || '—'}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );
}

function HeadersSection({ headers }) {
  if (!headers) return <Typography variant="body2" color="text.secondary">Dados não disponíveis.</Typography>;
  const encontrados = headers.headers_encontrados || [];
  const ausentes    = headers.headers_ausentes    || [];
  return (
    <Stack spacing={1.5}>
      {encontrados.map(h => (
        <Box key={h.header} sx={{ display: 'flex', alignItems: 'flex-start', gap: 2, p: 1.5, borderRadius: 1.5, backgroundColor: alpha('#00ff9d', 0.04), border: `1px solid ${alpha('#00ff9d', 0.12)}` }}>
          <Chip label="✓" size="small" color="success" sx={{ fontWeight: 800, minWidth: 32, height: 22, fontSize: '0.7rem' }} />
          <Box sx={{ flex: 1 }}>
            <Typography variant="body2" sx={{ fontWeight: 700, fontFamily: '"JetBrains Mono", monospace', fontSize: '0.8rem' }}>{h.header}</Typography>
            <Typography variant="caption" color="text.secondary" sx={{ wordBreak: 'break-all', display: 'block', mt: 0.3 }}>{h.valor}</Typography>
          </Box>
          <Chip label={`+${h.peso}`} size="small" color="success" variant="outlined" sx={{ fontSize: '0.68rem', fontWeight: 700 }} />
        </Box>
      ))}
      {ausentes.map(h => (
        <Box key={h.header} sx={{ display: 'flex', alignItems: 'flex-start', gap: 2, p: 1.5, borderRadius: 1.5, backgroundColor: alpha('#ff3b5c', 0.04), border: `1px solid ${alpha('#ff3b5c', 0.1)}` }}>
          <Chip label="✗" size="small" color="error" sx={{ fontWeight: 800, minWidth: 32, height: 22, fontSize: '0.7rem' }} />
          <Box sx={{ flex: 1 }}>
            <Typography variant="body2" sx={{ fontWeight: 700, fontFamily: '"JetBrains Mono", monospace', fontSize: '0.8rem' }}>{h.header}</Typography>
            <Typography variant="caption" color="text.secondary">{h.descricao}</Typography>
          </Box>
          <Chip label={`-${h.peso}`} size="small" color="error" variant="outlined" sx={{ fontSize: '0.68rem', fontWeight: 700 }} />
        </Box>
      ))}
    </Stack>
  );
}

/* ── Results section with Accordions ─────────────────────── */
function ResultsSection({ result, ip }) {
  const drift    = result.drift   || null;
  const shodan   = result.shodan  || null;
  const hasDrift = drift?.tem_mudancas;
  const numCves  = shodan?.cves?.length ?? 0;
  const hasCves  = numCves > 0;

  return (
    <Box className="fade-in-up">
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} md={4}><RiskCard result={result} /></Grid>
        <Grid item xs={12} md={8}><GeoCard result={result} ip={ip} /></Grid>
      </Grid>

      <Stack spacing={1.5}>
        {/* Portas Nmap */}
        <Accordion defaultExpanded>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
              <RouterIcon sx={{ color: 'secondary.main', fontSize: 20 }} />
              <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Portas Abertas (Nmap)</Typography>
              {result.portas_abertas?.length > 0 && (
                <Chip label={result.portas_abertas.length} size="small" color="secondary" sx={{ fontWeight: 700, height: 20, fontSize: '0.7rem' }} />
              )}
            </Box>
          </AccordionSummary>
          <AccordionDetails sx={{ pt: 0 }}><NmapSection portas={result.portas_abertas} /></AccordionDetails>
        </Accordion>

        {/* Vulnerabilidades Shodan */}
        <Accordion defaultExpanded={hasCves}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
              <BugReportIcon sx={{ color: hasCves ? '#ff3b5c' : 'text.disabled', fontSize: 20 }} />
              <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Vulnerabilidades (Shodan)</Typography>
              {hasCves && (
                <Chip
                  label={`${numCves} CVE${numCves !== 1 ? 's' : ''}`}
                  size="small"
                  sx={{ fontWeight: 700, height: 20, fontSize: '0.7rem', backgroundColor: alpha('#ff3b5c', 0.12), color: '#ff3b5c' }}
                />
              )}
              {shodan && !shodan.disponivel && (
                <Chip label="API Key não configurada" size="small" sx={{ height: 20, fontSize: '0.65rem', color: 'text.disabled' }} />
              )}
            </Box>
          </AccordionSummary>
          <AccordionDetails sx={{ pt: 0.5 }}><CveList shodan={shodan} /></AccordionDetails>
        </Accordion>

        {/* Drift */}
        <Accordion defaultExpanded={hasDrift}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
              <CompareArrowsIcon sx={{ color: hasDrift ? '#ffb830' : 'text.disabled', fontSize: 20 }} />
              <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Análise de Drift</Typography>
              {hasDrift && (
                <Chip label="Mudanças Detectadas" size="small" color="warning" sx={{ fontWeight: 700, height: 20, fontSize: '0.7rem' }} />
              )}
            </Box>
          </AccordionSummary>
          <AccordionDetails sx={{ pt: 0.5 }}><DriftViewer drift={drift} /></AccordionDetails>
        </Accordion>

        {/* Headers HTTP */}
        <Accordion>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
              <SecurityIcon sx={{ color: 'primary.main', fontSize: 20 }} />
              <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Headers de Segurança HTTP</Typography>
              {result.headers_seguranca && (
                <Chip
                  label={`Score: ${result.headers_seguranca.score_http ?? '—'}%`}
                  size="small"
                  sx={{ fontWeight: 700, height: 20, fontSize: '0.7rem', backgroundColor: alpha('#00d4ff', 0.12), color: 'primary.main' }}
                />
              )}
            </Box>
          </AccordionSummary>
          <AccordionDetails sx={{ pt: 0 }}><HeadersSection headers={result.headers_seguranca} /></AccordionDetails>
        </Accordion>
      </Stack>
    </Box>
  );
}

/* ── Main page ────────────────────────────────────────────── */
export default function IpAnalysis() {
  const [ip, setIp]           = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult]   = useState(null);
  const [error, setError]     = useState('');
  const [openSnackbar, setOpenSnackbar] = useState(false);

  const handleSearch = async (e) => {
    e?.preventDefault();
    if (!ip.trim()) return;
    setLoading(true);
    setError('');
    setResult(null);
    try {
      const res = await api.post('/analisar/', { ip: ip.trim() });
      setResult(res.data);
    } catch (err) {
      const msg = err.response?.status === 401 || err.response?.status === 403
        ? 'Erro de autenticação: verifique a API Key no .env.'
        : err.response?.data?.detail || err.message || 'Erro desconhecido.';
      setError(msg);
      setOpenSnackbar(true);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Container maxWidth="lg" sx={{ py: 5, px: { xs: 2, sm: 3 } }}>
      {/* HERO */}
      <Box sx={{ textAlign: 'center', mb: 6 }}>
        <Box sx={{
          display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
          width: 64, height: 64, borderRadius: '18px', mb: 2.5,
          background: 'linear-gradient(135deg, rgba(0,212,255,0.2), rgba(0,255,157,0.08))',
          border: '1px solid rgba(0,212,255,0.3)',
        }}>
          <GppBadIcon sx={{ color: 'primary.main', fontSize: 32 }} />
        </Box>
        <Typography variant="h4" gutterBottom sx={{ fontWeight: 800 }}>
          Análise de Reputação IP
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ maxWidth: 520, mx: 'auto' }}>
          Descubra a reputação, portas expostas e geolocalização de qualquer endereço IP em segundos.
        </Typography>
      </Box>

      {/* SEARCH BAR */}
      <Box
        component="form"
        onSubmit={handleSearch}
        sx={{ display: 'flex', gap: 1.5, mb: 5, maxWidth: 600, mx: 'auto' }}
      >
        <TextField
          fullWidth
          variant="outlined"
          placeholder="IPv4 ou IPv6... ex: 8.8.8.8"
          value={ip}
          onChange={(e) => setIp(e.target.value)}
          disabled={loading}
          inputProps={{ style: { fontFamily: '"JetBrains Mono", monospace', fontSize: '0.9rem' } }}
        />
        <Button
          variant="contained"
          type="submit"
          disabled={loading || !ip.trim()}
          sx={{ minWidth: 140, flexShrink: 0 }}
          startIcon={loading ? <CircularProgress size={18} color="inherit" /> : <SearchIcon />}
        >
          {loading ? 'Analisando…' : 'Escanear'}
        </Button>
      </Box>

      {/* LOADING SKELETON */}
      {loading && (
        <Stack spacing={3}>
          <Grid container spacing={3}>
            <Grid item xs={12} md={4}><Skeleton variant="rectangular" height={260} sx={{ borderRadius: 2 }} /></Grid>
            <Grid item xs={12} md={8}><Skeleton variant="rectangular" height={260} sx={{ borderRadius: 2 }} /></Grid>
          </Grid>
          {[1, 2].map(i => <Skeleton key={i} variant="rectangular" height={80} sx={{ borderRadius: 2 }} />)}
        </Stack>
      )}

      {/* RESULTS */}
      {result && !loading && <ResultsSection result={result} ip={ip} />}

      <Snackbar open={openSnackbar} autoHideDuration={6000} onClose={() => setOpenSnackbar(false)} anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}>
        <Alert onClose={() => setOpenSnackbar(false)} severity="error" variant="filled" sx={{ fontWeight: 600, borderRadius: 2 }}>
          {error}
        </Alert>
      </Snackbar>
    </Container>
  );
}
