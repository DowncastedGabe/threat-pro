/**
 * pages/OsintDorker.jsx — Busca OSINT via Tor + DuckDuckGo
 *
 * Permite ao analista encontrar diretórios expostos de um domínio
 * utilizando a query "intitle:index.of" roteada pelo Tor para anonimato.
 */

import React, { useState, useEffect } from 'react';
import {
  Container, Box, Typography, TextField, Button, CircularProgress,
  Card, CardContent, Chip, Stack, Alert, alpha, Skeleton, Tooltip,
  Divider, Link, IconButton,
} from '@mui/material';
import SearchIcon         from '@mui/icons-material/Search';
import SecurityIcon       from '@mui/icons-material/Security';
import FolderOpenIcon     from '@mui/icons-material/FolderOpen';
import RouterIcon         from '@mui/icons-material/Router';
import RefreshIcon        from '@mui/icons-material/Refresh';
import OpenInNewIcon      from '@mui/icons-material/OpenInNew';
import CheckCircleIcon    from '@mui/icons-material/CheckCircle';
import ErrorIcon          from '@mui/icons-material/Error';
import api from '../api';

/* ── Status do Tor ───────────────────────────────────────────────────────── */
function TorStatus() {
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(true);

  const verificar = async () => {
    setLoading(true);
    try {
      const res = await api.get('/osint/tor-status/');
      setStatus(res.data);
    } catch {
      setStatus({ ativo: false, ip_tor: null, erro: 'Não foi possível verificar o Tor.' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { verificar(); }, []);

  return (
    <Box
      sx={{
        display: 'inline-flex', alignItems: 'center', gap: 1, px: 2, py: 1,
        borderRadius: 2,
        border: loading
          ? '1px solid rgba(255,255,255,0.1)'
          : status?.ativo
            ? '1px solid rgba(0,255,157,0.25)'
            : '1px solid rgba(255,59,92,0.25)',
        backgroundColor: loading
          ? 'rgba(255,255,255,0.03)'
          : status?.ativo
            ? alpha('#00ff9d', 0.05)
            : alpha('#ff3b5c', 0.05),
      }}
    >
      <RouterIcon sx={{ fontSize: 16, color: loading ? 'text.disabled' : status?.ativo ? '#00ff9d' : '#ff3b5c' }} />
      {loading ? (
        <Typography variant="caption" color="text.disabled">Verificando Tor...</Typography>
      ) : status?.ativo ? (
        <>
          <CheckCircleIcon sx={{ fontSize: 14, color: '#00ff9d' }} />
          <Typography variant="caption" sx={{ color: '#00ff9d', fontWeight: 600 }}>Tor Ativo</Typography>
          {status.ip_tor && (
            <Typography variant="caption" color="text.disabled" sx={{ fontFamily: '"JetBrains Mono", monospace', fontSize: '0.7rem' }}>
              — {status.ip_tor}
            </Typography>
          )}
        </>
      ) : (
        <>
          <ErrorIcon sx={{ fontSize: 14, color: '#ff3b5c' }} />
          <Typography variant="caption" sx={{ color: '#ff3b5c', fontWeight: 600 }}>Tor Indisponível</Typography>
          <Typography variant="caption" color="text.disabled"> — busca usará conexão direta</Typography>
        </>
      )}
      <Tooltip title="Verificar novamente">
        <IconButton size="small" onClick={verificar} sx={{ color: 'text.disabled', p: 0.3, ml: 0.5 }}>
          <RefreshIcon sx={{ fontSize: 14 }} />
        </IconButton>
      </Tooltip>
    </Box>
  );
}

/* ── Card de resultado ───────────────────────────────────────────────────── */
function ResultCard({ resultado, idx }) {
  return (
    <Card
      sx={{
        border: '1px solid rgba(255,255,255,0.06)',
        transition: 'border-color 0.2s, transform 0.2s',
        '&:hover': {
          borderColor: alpha('#00d4ff', 0.25),
          transform: 'translateX(4px)',
        },
      }}
    >
      <CardContent sx={{ p: 2, '&:last-child': { pb: 2 } }}>
        <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1.5 }}>
          <Box sx={{
            width: 32, height: 32, borderRadius: '8px', flexShrink: 0,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            backgroundColor: alpha('#ffb830', 0.1), border: '1px solid rgba(255,184,48,0.2)',
          }}>
            <FolderOpenIcon sx={{ fontSize: 16, color: '#ffb830' }} />
          </Box>
          <Box sx={{ flex: 1, minWidth: 0 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
              <Chip
                label={`#${idx + 1}`}
                size="small"
                sx={{ height: 18, fontSize: '0.65rem', backgroundColor: alpha('#00d4ff', 0.08), color: 'primary.main' }}
              />
              <Typography
                variant="body2"
                sx={{ fontWeight: 600, color: 'white', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
              >
                {resultado.titulo || 'Sem título'}
              </Typography>
              <Tooltip title="Abrir URL">
                <IconButton
                  size="small"
                  component={Link}
                  href={resultado.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  sx={{ color: 'text.disabled', p: 0.3, flexShrink: 0, '&:hover': { color: 'primary.main' } }}
                >
                  <OpenInNewIcon sx={{ fontSize: 14 }} />
                </IconButton>
              </Tooltip>
            </Box>
            <Typography
              variant="caption"
              sx={{
                fontFamily: '"JetBrains Mono", monospace',
                color: 'primary.main',
                fontSize: '0.7rem',
                display: 'block',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
                mb: 0.5,
              }}
            >
              {resultado.url}
            </Typography>
            {resultado.snippet && (
              <Typography variant="caption" color="text.secondary" sx={{ fontSize: '0.73rem', lineHeight: 1.5 }}>
                {resultado.snippet}
              </Typography>
            )}
          </Box>
        </Box>
      </CardContent>
    </Card>
  );
}

/* ── Página principal ────────────────────────────────────────────────────── */
export default function OsintDorker() {
  const [dominio, setDominio] = useState('');
  const [loading, setLoading] = useState(false);
  const [resultado, setResultado] = useState(null);
  const [erro, setErro] = useState('');

  const handleBusca = async (e) => {
    e?.preventDefault();
    const dom = dominio.trim();
    if (!dom) return;
    setLoading(true);
    setErro('');
    setResultado(null);
    try {
      const res = await api.get('/osint/dork/', { params: { dominio: dom } });
      setResultado(res.data);
    } catch (err) {
      const msg = err.response?.data?.detail || err.message || 'Erro ao executar busca OSINT.';
      setErro(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Container maxWidth="lg" sx={{ py: 5, px: { xs: 2, sm: 3 } }}>
      {/* Hero */}
      <Box sx={{ mb: 5 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 1 }}>
          <Box sx={{
            width: 44, height: 44, borderRadius: '12px',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            background: 'linear-gradient(135deg, rgba(255,184,48,0.2), rgba(255,107,53,0.08))',
            border: '1px solid rgba(255,184,48,0.25)',
          }}>
            <SecurityIcon sx={{ color: '#ffb830', fontSize: 22 }} />
          </Box>
          <Box>
            <Typography variant="h4" sx={{ fontWeight: 800, lineHeight: 1.1 }}>
              OSINT Dorker
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Encontre diretórios e arquivos expostos via DuckDuckGo · Anonimato via Tor
            </Typography>
          </Box>
        </Box>
      </Box>

      {/* Status do Tor */}
      <Box sx={{ mb: 3 }}>
        <TorStatus />
      </Box>

      {/* Formulário */}
      <Box component="form" onSubmit={handleBusca} sx={{ display: 'flex', gap: 1.5, mb: 4, maxWidth: 640 }}>
        <TextField
          fullWidth
          variant="outlined"
          placeholder="exemplo.com.br"
          value={dominio}
          onChange={(e) => setDominio(e.target.value)}
          disabled={loading}
          inputProps={{ style: { fontFamily: '"JetBrains Mono", monospace', fontSize: '0.9rem' } }}
          helperText={`Query: site:${dominio || '<dominio>'} intitle:"index of"`}
        />
        <Button
          variant="contained"
          type="submit"
          disabled={loading || !dominio.trim()}
          sx={{
            minWidth: 160, flexShrink: 0,
            background: 'linear-gradient(135deg, #ffb830, #ff6b35)',
            '&:hover': { background: 'linear-gradient(135deg, #ffc94d, #ff7d4d)' },
          }}
          startIcon={loading ? <CircularProgress size={18} color="inherit" /> : <SearchIcon />}
        >
          {loading ? 'Buscando...' : 'Buscar via Tor'}
        </Button>
      </Box>

      {/* Loading skeleton */}
      {loading && (
        <Stack spacing={2}>
          {[1, 2, 3].map(i => (
            <Skeleton key={i} variant="rectangular" height={80} sx={{ borderRadius: 2 }} />
          ))}
        </Stack>
      )}

      {/* Erro */}
      {erro && !loading && (
        <Alert severity="error" sx={{ borderRadius: 2, mb: 3 }}>{erro}</Alert>
      )}

      {/* Resultados */}
      {resultado && !loading && (
        <Box className="fade-in-up">
          {/* Meta info */}
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 3, flexWrap: 'wrap' }}>
            <Typography variant="body2" color="text.secondary">
              Busca por{' '}
              <strong style={{ color: 'white' }}>{resultado.dominio}</strong>
            </Typography>
            <Chip
              label={resultado.via_tor ? '🧅 Via Tor' : '⚠ Conexão Direta'}
              size="small"
              sx={{
                fontWeight: 700, fontSize: '0.68rem',
                backgroundColor: resultado.via_tor ? alpha('#00ff9d', 0.1) : alpha('#ffb830', 0.1),
                color: resultado.via_tor ? '#00ff9d' : '#ffb830',
              }}
            />
            <Chip
              label={`${resultado.resultados.length} resultado${resultado.resultados.length !== 1 ? 's' : ''}`}
              size="small"
              sx={{ fontWeight: 700, fontSize: '0.68rem', backgroundColor: alpha('#00d4ff', 0.08), color: 'primary.main' }}
            />

            {/* Query usada */}
            <Typography
              variant="caption"
              sx={{
                ml: 'auto', fontFamily: '"JetBrains Mono", monospace',
                color: 'text.disabled', fontSize: '0.72rem',
              }}
            >
              {resultado.query}
            </Typography>
          </Box>

          {/* Alerta de fallback */}
          {!resultado.via_tor && (
            <Alert severity="warning" sx={{ mb: 3, borderRadius: 2, fontSize: '0.8rem' }}>
              Tor indisponível — busca executada sem anonimato. Verifique se o container Tor está em execução.
            </Alert>
          )}

          {resultado.erro && (
            <Alert severity="info" sx={{ mb: 3, borderRadius: 2, fontSize: '0.8rem' }}>
              {resultado.erro}
            </Alert>
          )}

          {resultado.resultados.length === 0 ? (
            <Box sx={{
              textAlign: 'center', py: 8,
              border: '1px dashed rgba(255,255,255,0.08)',
              borderRadius: 3,
              backgroundColor: 'rgba(255,255,255,0.01)',
            }}>
              <FolderOpenIcon sx={{ fontSize: 48, color: alpha('#fff', 0.1), mb: 2 }} />
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 1 }}>
                Nenhum diretório exposto encontrado
              </Typography>
              <Typography variant="body2" color="text.secondary">
                O domínio pode não ter diretórios públicos indexados ou o DuckDuckGo não os encontrou.
              </Typography>
            </Box>
          ) : (
            <Stack spacing={1.5}>
              {resultado.resultados.map((r, idx) => (
                <ResultCard key={`${r.url}-${idx}`} resultado={r} idx={idx} />
              ))}
            </Stack>
          )}
        </Box>
      )}
    </Container>
  );
}
