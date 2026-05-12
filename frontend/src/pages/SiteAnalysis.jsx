import React, { useState } from 'react';
import {
  Box, Container, Typography, TextField, Button, CircularProgress,
  Card, CardContent, Grid, Snackbar, Alert, Chip, Stack, alpha,
  Accordion, AccordionSummary, AccordionDetails, LinearProgress, Skeleton,
} from '@mui/material';
import TravelExploreIcon from '@mui/icons-material/TravelExplore';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import HttpsIcon from '@mui/icons-material/Https';
import DnsIcon from '@mui/icons-material/Dns';
import SecurityIcon from '@mui/icons-material/Security';
import FingerprintIcon from '@mui/icons-material/Fingerprint';
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined';
import RouterIcon from '@mui/icons-material/Router';
import api from '../api';

/* ── Helpers ──────────────────────────────────────────────── */
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
        {value !== undefined && value !== null && value !== '' ? String(value) : '—'}
      </Typography>
    </Box>
  );
}

/* ── Sections (pure components, recebem dados via props) ─── */
function TlsSection({ tls }) {
  if (!tls) {
    return (
      <Typography variant="body2" color="text.secondary">
        Dados de TLS/SSL não disponíveis para este domínio.
      </Typography>
    );
  }

  const valido = tls.valido;
  const diasRestantes = tls.dias_restantes ?? 0;
  const progress = Math.max(0, Math.min(100, (diasRestantes / 365) * 100));

  return (
    <Stack spacing={2}>
      <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
        <Chip
          label={valido ? '✓ Certificado Válido' : '✗ Certificado Inválido/Expirado'}
          color={valido ? 'success' : 'error'}
          sx={{ fontWeight: 700 }}
        />
        {tls.dias_restantes !== undefined && (
          <Chip
            label={`${diasRestantes} dias restantes`}
            size="small"
            color={diasRestantes < 30 ? 'warning' : 'default'}
          />
        )}
      </Box>

      {tls.dias_restantes !== undefined && (
        <Box>
          <Typography variant="caption" color="text.secondary" sx={{ mb: 0.8, display: 'block' }}>
            Validade do certificado
          </Typography>
          <LinearProgress
            variant="determinate"
            value={progress}
            color={diasRestantes < 30 ? 'warning' : 'success'}
          />
        </Box>
      )}

      <Grid container spacing={0}>
        <Grid item xs={12} sm={6}><DataRow label="Hostname"      value={tls.hostname}          mono /></Grid>
        <Grid item xs={12} sm={6}><DataRow label="Common Name"   value={tls.common_name}        mono /></Grid>
        <Grid item xs={12} sm={6}><DataRow label="Emitido em"    value={tls.emitido_em} /></Grid>
        <Grid item xs={12} sm={6}><DataRow label="Expira em"     value={tls.expira_em} /></Grid>
        <Grid item xs={12}>       <DataRow label="Emissor (CA)"  value={tls.issuer_common_name} /></Grid>
      </Grid>
    </Stack>
  );
}

function DnsSection({ dns }) {
  if (!dns) {
    return (
      <Typography variant="body2" color="text.secondary">
        Dados de DNS não disponíveis para este domínio.
      </Typography>
    );
  }

  const registros = dns.registros || {};
  const entries = Object.entries(registros);

  if (entries.length === 0) {
    return <Typography variant="body2" color="text.secondary">Nenhum registro DNS encontrado.</Typography>;
  }

  return (
    <Stack spacing={1.5}>
      {entries.map(([tipo, values]) => (
        <Box key={tipo}>
          <Typography
            variant="caption"
            sx={{ color: 'primary.main', fontWeight: 700, mb: 0.5, display: 'block', letterSpacing: '0.1em' }}
          >
            {tipo.toUpperCase()}
          </Typography>
          {Array.isArray(values) && values.length > 0 ? (
            values.map((v, i) => (
              <Typography
                key={i}
                variant="body2"
                sx={{
                  fontFamily: '"JetBrains Mono", monospace',
                  color: 'text.secondary',
                  fontSize: '0.82rem',
                  pl: 1.5,
                  borderLeft: '2px solid rgba(0,212,255,0.2)',
                  mb: 0.3,
                }}
              >
                {v}
              </Typography>
            ))
          ) : (
            <Typography variant="body2" color="text.disabled" sx={{ pl: 1.5 }}>
              Sem registros
            </Typography>
          )}
        </Box>
      ))}
    </Stack>
  );
}

function HeadersSection({ headers }) {
  if (!headers) {
    return (
      <Typography variant="body2" color="text.secondary">
        Dados de headers de segurança não disponíveis.
      </Typography>
    );
  }

  const encontrados = headers.headers_encontrados || [];
  const ausentes    = headers.headers_ausentes    || [];
  const score       = headers.score_http;

  return (
    <Stack spacing={1.5}>
      {score !== undefined && (
        <Box sx={{ mb: 1 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.8 }}>
            <Typography variant="caption" color="text.secondary">Pontuação de Segurança HTTP</Typography>
            <Typography
              variant="caption"
              sx={{
                fontWeight: 700,
                color: score >= 80 ? '#00ff9d' : score >= 50 ? '#ffb830' : '#ff3b5c',
              }}
            >
              {score}%
            </Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={score}
            color={score >= 80 ? 'success' : score >= 50 ? 'warning' : 'error'}
          />
        </Box>
      )}

      {encontrados.map((h) => (
        <Box
          key={h.header}
          sx={{
            display: 'flex', alignItems: 'flex-start', gap: 2, p: 1.5,
            borderRadius: 1.5,
            backgroundColor: alpha('#00ff9d', 0.04),
            border: `1px solid ${alpha('#00ff9d', 0.12)}`,
          }}
        >
          <Chip label="✓" size="small" color="success" sx={{ fontWeight: 800, minWidth: 32, height: 22, fontSize: '0.7rem' }} />
          <Box sx={{ flex: 1 }}>
            <Typography variant="body2" sx={{ fontWeight: 700, fontFamily: '"JetBrains Mono", monospace', fontSize: '0.8rem' }}>
              {h.header}
            </Typography>
            <Typography variant="caption" color="text.secondary" sx={{ wordBreak: 'break-all', display: 'block', mt: 0.3 }}>
              {h.valor}
            </Typography>
          </Box>
          <Chip label={`+${h.peso}`} size="small" color="success" variant="outlined" sx={{ fontSize: '0.68rem', fontWeight: 700 }} />
        </Box>
      ))}

      {ausentes.map((h) => (
        <Box
          key={h.header}
          sx={{
            display: 'flex', alignItems: 'flex-start', gap: 2, p: 1.5,
            borderRadius: 1.5,
            backgroundColor: alpha('#ff3b5c', 0.04),
            border: `1px solid ${alpha('#ff3b5c', 0.1)}`,
          }}
        >
          <Chip label="✗" size="small" color="error" sx={{ fontWeight: 800, minWidth: 32, height: 22, fontSize: '0.7rem' }} />
          <Box sx={{ flex: 1 }}>
            <Typography variant="body2" sx={{ fontWeight: 700, fontFamily: '"JetBrains Mono", monospace', fontSize: '0.8rem' }}>
              {h.header}
            </Typography>
            <Typography variant="caption" color="text.secondary">{h.descricao}</Typography>
          </Box>
          <Chip label={`-${h.peso}`} size="small" color="error" variant="outlined" sx={{ fontSize: '0.68rem', fontWeight: 700 }} />
        </Box>
      ))}
    </Stack>
  );
}

function FingerprintSection({ fp }) {
  if (!fp) {
    return (
      <Typography variant="body2" color="text.secondary">
        Dados de fingerprint HTTP não disponíveis.
      </Typography>
    );
  }

  return (
    <Stack spacing={1.5}>
      <Grid container spacing={0}>
        <Grid item xs={12} sm={6}><DataRow label="URL Final"     value={fp.url_final}    mono /></Grid>
        <Grid item xs={12} sm={6}><DataRow label="Status Code"   value={fp.status_code} /></Grid>
        <Grid item xs={12} sm={6}><DataRow label="Servidor"      value={fp.server} /></Grid>
        <Grid item xs={12} sm={6}><DataRow label="Powered By"    value={fp.powered_by} /></Grid>
        <Grid item xs={12} sm={6}><DataRow label="WAF Detectado" value={fp.possivel_waf} /></Grid>
      </Grid>

      {fp.tecnologias_detectadas?.length > 0 && (
        <Box>
          <Typography variant="caption" color="text.secondary" sx={{ mb: 1, display: 'block' }}>
            Tecnologias Detectadas
          </Typography>
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
            {fp.tecnologias_detectadas.map((t) => (
              <Chip key={t} label={t} size="small" variant="outlined" sx={{ fontSize: '0.75rem' }} />
            ))}
          </Box>
        </Box>
      )}

      {fp.cookies_detectados?.length > 0 && (
        <Box>
          <Typography variant="caption" color="text.secondary" sx={{ mb: 1, display: 'block' }}>
            Cookies Detectados
          </Typography>
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
            {fp.cookies_detectados.map((c) => (
              <Chip
                key={c}
                label={c}
                size="small"
                sx={{ fontFamily: '"JetBrains Mono", monospace', fontSize: '0.72rem', backgroundColor: alpha('#fff', 0.05) }}
              />
            ))}
          </Box>
        </Box>
      )}
    </Stack>
  );
}

/* ── Results section — só renderiza com dados reais ────────── */
function InfraHealthSection({ infra }) {
  const itens = infra?.itens || [];

  if (!infra || itens.length === 0) {
    return (
      <Typography variant="body2" color="text.secondary">
        Nenhum ip4, ip6 ou include SPF encontrado para checagem.
      </Typography>
    );
  }

  const statusColor = (status) => {
    if (status === 'Online') return 'success';
    if (status === 'Offline') return 'error';
    return 'default';
  };

  const statusBg = (status) => {
    if (status === 'Online') return alpha('#00ff9d', 0.04);
    if (status === 'Offline') return alpha('#ff3b5c', 0.04);
    return alpha('#ffffff', 0.035);
  };

  const statusBorder = (status) => {
    if (status === 'Online') return alpha('#00ff9d', 0.14);
    if (status === 'Offline') return alpha('#ff3b5c', 0.14);
    return alpha('#ffffff', 0.08);
  };

  const resumo = itens.reduce(
    (acc, item) => {
      if (item.status === 'Online') acc.online += 1;
      else if (item.status === 'Offline') acc.offline += 1;
      else acc.inconclusivo += 1;
      return acc;
    },
    { online: 0, offline: 0, inconclusivo: 0 }
  );

  return (
    <Stack spacing={1.5}>
      <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
        <Chip label={`${resumo.online} online`} size="small" color="success" sx={{ fontWeight: 700 }} />
        <Chip label={`${resumo.offline} offline`} size="small" color="error" sx={{ fontWeight: 700 }} />
        <Chip label={`${resumo.inconclusivo} inconclusivo`} size="small" sx={{ fontWeight: 700 }} />
      </Box>

      {itens.map((item, index) => {
        const alvo = item.ip_testado || item.valor;
        const nome = item.servico ? `${item.servico} - ${alvo}` : alvo;
        const detalhe = [
          item.tipo?.toUpperCase(),
          item.ip_testado && item.valor !== item.ip_testado ? item.valor : null,
          item.porta ? `TCP ${item.porta}` : null,
          item.latencia_ms !== null && item.latencia_ms !== undefined ? `${item.latencia_ms} ms` : null,
        ].filter(Boolean).join(' | ');

        return (
          <Box
            key={`${item.tipo}-${item.valor}-${index}`}
            sx={{
              display: 'flex',
              alignItems: { xs: 'flex-start', sm: 'center' },
              justifyContent: 'space-between',
              gap: 1.5,
              p: 1.5,
              borderRadius: 1.5,
              backgroundColor: statusBg(item.status),
              border: `1px solid ${statusBorder(item.status)}`,
              flexDirection: { xs: 'column', sm: 'row' },
            }}
          >
            <Box sx={{ minWidth: 0 }}>
              <Typography
                variant="body2"
                sx={{
                  fontWeight: 700,
                  fontFamily: '"JetBrains Mono", monospace',
                  wordBreak: 'break-all',
                }}
              >
                {nome}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                {detalhe || item.erro || 'SPF autorizado'}
              </Typography>
            </Box>
            <Chip
              label={item.status || 'Inconclusivo'}
              size="small"
              color={statusColor(item.status)}
              sx={{ fontWeight: 800, minWidth: 112 }}
            />
          </Box>
        );
      })}
    </Stack>
  );
}

function ResultsSection({ result }) {
  const tls     = result.certificados_tls || null;
  const dns     = result.dns_records      || null;
  const headers = result.headers_seguranca|| null;
  const fp      = result.http_fingerprint || null;
  const infra   = result.infra_status || null;
  const osint   = result.diretorios_expostos || null;
  const rdap    = result.rdap || null;

  const tlsBadge   = tls?.valido !== undefined ? (tls.valido ? 'Válido' : 'Inválido') : null;
  const scoreBadge = headers?.score_http !== undefined ? `${headers.score_http}%` : null;
  const wafBadge   = fp?.possivel_waf || null;
  const infraOnline = infra?.itens?.filter((item) => item.status === 'Online').length || 0;
  const infraTotal = infra?.itens?.length || 0;

  const brute = osint?.bruteforce || [];
  const dorks = osint?.dorks || [];
  const hasOsint = brute.length > 0 || dorks.length > 0;
  
  // Custom component for OSINT Section
  const OsintSection = () => {
    if (!osint) return <Typography variant="body2" color="text.secondary">Dados OSINT não disponíveis.</Typography>;
    if (!hasOsint) return <Typography variant="body2" color="text.secondary">Nenhum vazamento ou diretório exposto encontrado.</Typography>;
    
    return (
      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
        {brute.length > 0 && (
          <Alert severity="error" icon={<SecurityIcon />} sx={{ borderRadius: 2 }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
              Diretórios Expostos ({brute.length}) - Bruteforce
            </Typography>
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
              {brute.map((b, i) => (
                <Box key={i} sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                  <Typography variant="body2" sx={{ fontFamily: '"JetBrains Mono", monospace', fontWeight: 600 }}>{b.url}</Typography>
                  <Typography variant="caption" color="text.secondary">- {b.status} {b.observacao}</Typography>
                </Box>
              ))}
            </Box>
          </Alert>
        )}
        {dorks.length > 0 && (
          <Alert severity="warning" icon={<TravelExploreIcon />} sx={{ borderRadius: 2 }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
              Vazamentos Indexados (DuckDuckGo Dorks)
            </Typography>
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
              {dorks.map((d, i) => (
                <Box key={i} sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                  <Typography variant="body2" sx={{ fontWeight: 600 }}>
                    <a href={d.url} target="_blank" rel="noreferrer" style={{ color: 'inherit' }}>{d.url}</a>
                  </Typography>
                  <Typography variant="caption" color="text.secondary">- {d.titulo}</Typography>
                </Box>
              ))}
            </Box>
          </Alert>
        )}
      </Box>
    );
  };

  const accordions = [
    {
      key:       'tls',
      label:     'TLS / SSL',
      icon:      <HttpsIcon sx={{ color: '#00ff9d', fontSize: 20 }} />,
      badge:     tlsBadge,
      badgeColor:tls?.valido ? 'success' : 'error',
      content:   <TlsSection tls={tls} />,
      open:      true,
    },
    {
      key:       'dns',
      label:     'Registros DNS',
      icon:      <DnsIcon sx={{ color: '#bf5af2', fontSize: 20 }} />,
      badge:     null,
      content:   <DnsSection dns={dns} />,
      open:      false,
    },
    {
      key:       'infra',
      label:     'Ecossistema de Infraestrutura',
      icon:      <RouterIcon sx={{ color: '#00ff9d', fontSize: 20 }} />,
      badge:     infraTotal ? `${infraOnline}/${infraTotal} online` : null,
      badgeColor:infraTotal && infraOnline === infraTotal ? 'success' : 'default',
      content:   <InfraHealthSection infra={infra} />,
      open:      Boolean(infraTotal),
    },
    {
      key:       'headers',
      label:     'Headers de Segurança',
      icon:      <SecurityIcon sx={{ color: '#00d4ff', fontSize: 20 }} />,
      badge:     scoreBadge,
      badgeColor:'primary',
      content:   <HeadersSection headers={headers} />,
      open:      false,
    },
    {
      key:       'fingerprint',
      label:     'HTTP Fingerprint',
      icon:      <FingerprintIcon sx={{ color: '#ffb830', fontSize: 20 }} />,
      badge:     wafBadge,
      badgeColor:'warning',
      content:   <FingerprintSection fp={fp} />,
      open:      false,
    },
    {
      key:       'rdap',
      label:     'Informações WHOIS / RDAP',
      icon:      <InfoOutlinedIcon sx={{ color: '#00d4ff', fontSize: 20 }} />,
      badge:     rdap?.handle || null,
      content:   (
        <Box>
          {rdap ? (
            <Grid container spacing={0}>
              <Grid item xs={12} sm={6}><DataRow label="Entidade" value={rdap.entities?.[0]?.handle} /></Grid>
              <Grid item xs={12} sm={6}><DataRow label="Status" value={rdap.status?.[0]} /></Grid>
              <Grid item xs={12} sm={6}><DataRow label="Data de Criação" value={rdap.events?.find(e => e.eventAction === 'registration')?.eventDate} /></Grid>
              <Grid item xs={12} sm={6}><DataRow label="Última Atualização" value={rdap.events?.find(e => e.eventAction === 'last changed')?.eventDate} /></Grid>
            </Grid>
          ) : (
            <Typography variant="body2" color="text.secondary">Dados RDAP não disponíveis.</Typography>
          )}
        </Box>
      ),
      open:      false,
    },
    {
      key:       'osint',
      label:     'OSINT & Diretórios (Rede Tor)',
      icon:      <TravelExploreIcon sx={{ color: '#ff3b5c', fontSize: 20 }} />,
      badge:     hasOsint ? `${brute.length + dorks.length} Alertas` : 'Seguro',
      badgeColor:hasOsint ? 'error' : 'success',
      content:   <OsintSection />,
      open:      hasOsint,
    },
  ];

  return (
    <Box className="fade-in-up">
      {/* Summary bar */}
      <Box
        sx={{
          display: 'flex', alignItems: 'center', gap: 1.5, mb: 3, p: 2,
          borderRadius: 2,
          backgroundColor: alpha('#00d4ff', 0.04),
          border: '1px solid rgba(0,212,255,0.12)',
        }}
      >
        <InfoOutlinedIcon sx={{ color: 'primary.main', fontSize: 20 }} />
        <Typography variant="body2" sx={{ fontWeight: 600, color: 'primary.light' }}>
          {result.url}
        </Typography>
      </Box>

      <Stack spacing={1.5}>
        {accordions.map((acc) => (
          <Accordion key={acc.key} defaultExpanded={acc.open}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                {acc.icon}
                <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                  {acc.label}
                </Typography>
                {acc.badge && (
                  <Chip
                    label={acc.badge}
                    size="small"
                    color={acc.badgeColor || 'default'}
                    sx={{ fontWeight: 700, height: 20, fontSize: '0.7rem' }}
                  />
                )}
              </Box>
            </AccordionSummary>
            <AccordionDetails sx={{ pt: 0.5 }}>
              {acc.content}
            </AccordionDetails>
          </Accordion>
        ))}
      </Stack>
    </Box>
  );
}

/* ── Main Page ─────────────────────────────────────────────── */
export default function SiteAnalysis() {
  const [url, setUrl]         = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult]   = useState(null);
  const [error, setError]     = useState('');
  const [openSnackbar, setOpenSnackbar] = useState(false);

  const handleSearch = async (e) => {
    e?.preventDefault();
    if (!url.trim()) return;
    setLoading(true);
    setError('');
    setResult(null);
    try {
      const res = await api.post('/analisar-site/', { url: url.trim() });
      setResult(res.data);
    } catch (err) {
      const msg =
        err.response?.status === 401 || err.response?.status === 403
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
        <Box
          sx={{
            display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
            width: 64, height: 64, borderRadius: '18px', mb: 2.5,
            background: 'linear-gradient(135deg, rgba(0,255,157,0.15), rgba(0,212,255,0.05))',
            border: '1px solid rgba(0,255,157,0.3)',
          }}
        >
          <TravelExploreIcon sx={{ color: 'secondary.main', fontSize: 32 }} />
        </Box>
        <Typography variant="h4" gutterBottom sx={{ fontWeight: 800 }}>
          Análise de Domínios e Sites
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ maxWidth: 520, mx: 'auto' }}>
          Verifique headers de segurança, certificados TLS/SSL, registros DNS e fingerprint HTTP.
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
          placeholder="Domínio ou URL — ex: google.com"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          disabled={loading}
          inputProps={{ style: { fontFamily: '"JetBrains Mono", monospace', fontSize: '0.9rem' } }}
        />
        <Button
          variant="contained"
          color="secondary"
          type="submit"
          disabled={loading || !url.trim()}
          sx={{ minWidth: 140, flexShrink: 0 }}
          startIcon={
            loading
              ? <CircularProgress size={18} color="inherit" />
              : <TravelExploreIcon />
          }
        >
          {loading ? 'Analisando…' : 'Escanear'}
        </Button>
      </Box>

      {/* LOADING SKELETONS */}
      {loading && (
        <Stack spacing={1.5}>
          {[1, 2, 3, 4].map((i) => (
            <Skeleton key={i} variant="rectangular" height={72} sx={{ borderRadius: 2 }} />
          ))}
        </Stack>
      )}

      {/* RESULTS — só renderiza quando há resultado e não está carregando */}
      {result && !loading && <ResultsSection result={result} />}

      {/* ERROR SNACKBAR */}
      <Snackbar
        open={openSnackbar}
        autoHideDuration={6000}
        onClose={() => setOpenSnackbar(false)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert
          onClose={() => setOpenSnackbar(false)}
          severity="error"
          variant="filled"
          sx={{ fontWeight: 600, borderRadius: 2 }}
        >
          {error}
        </Alert>
      </Snackbar>
    </Container>
  );
}
