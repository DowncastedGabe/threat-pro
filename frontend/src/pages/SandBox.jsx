import React, { useCallback, useRef, useState } from 'react';
import {
  Alert, Box, Button, Chip, CircularProgress, Container,
  IconButton, LinearProgress, List, ListItem, ListItemIcon,
  ListItemText, Paper, Snackbar, Stack, Tab, Tabs, Tooltip, Typography,
} from '@mui/material';
import ArrowForwardIcon    from '@mui/icons-material/ArrowForward';
import BugReportIcon       from '@mui/icons-material/BugReport';
import CheckCircleIcon     from '@mui/icons-material/CheckCircle';
import CloudUploadIcon     from '@mui/icons-material/CloudUpload';
import DeleteIcon          from '@mui/icons-material/Delete';
import ErrorIcon           from '@mui/icons-material/Error';
import FingerprintIcon     from '@mui/icons-material/Fingerprint';
import InsertDriveFileIcon from '@mui/icons-material/InsertDriveFile';
import LinkIcon            from '@mui/icons-material/Link';
import SendIcon            from '@mui/icons-material/Send';
import VpnLockIcon         from '@mui/icons-material/VpnLock';
import WarningIcon         from '@mui/icons-material/Warning';
import api from '../api';

const STATUS_META = {
  limpo:         { color: '#00ff9d', icon: <CheckCircleIcon />, label: 'Limpo' },
  suspeito:      { color: '#ffd600', icon: <WarningIcon />,     label: 'Suspeito' },
  malicioso:     { color: '#ff1744', icon: <ErrorIcon />,       label: 'Malicioso' },
  nao_analisado: { color: '#78909c', icon: <BugReportIcon />,   label: 'Não Analisado' },
  segura:        { color: '#00ff9d', icon: <CheckCircleIcon />, label: 'Segura' },
  suspeita:      { color: '#ffd600', icon: <WarningIcon />,     label: 'Suspeita' },
  maliciosa:     { color: '#ff1744', icon: <ErrorIcon />,       label: 'Maliciosa' },
  desconhecida:  { color: '#78909c', icon: <BugReportIcon />,   label: 'Desconhecida' },
};

const fmt = (bytes) => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(2)} MB`;
};

function DetectionBar({ detected, total }) {
  const pct   = total > 0 ? Math.round((detected / total) * 100) : 0;
  const color = pct === 0 ? '#00ff9d' : pct < 15 ? '#ffd600' : '#ff1744';
  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
        <Typography variant="body2" sx={{ color, fontWeight: 700 }}>
          {detected}/{total} motores detectaram
        </Typography>
        <Typography variant="body2" sx={{ color, fontWeight: 700 }}>{pct}%</Typography>
      </Box>
      <LinearProgress
        variant="determinate"
        value={pct}
        sx={{
          height: 10, borderRadius: 5,
          bgcolor: 'rgba(255,255,255,0.07)',
          '& .MuiLinearProgress-bar': {
            background: pct === 0
              ? 'linear-gradient(90deg,#00ff9d,#00d4ff)'
              : pct < 15
                ? 'linear-gradient(90deg,#ffd600,#ff9100)'
                : 'linear-gradient(90deg,#ff1744,#ff6d00)',
            borderRadius: 5,
          },
        }}
      />
    </Box>
  );
}

function HashRow({ label, value }) {
  return (
    <Box sx={{ display: 'flex', gap: 1, alignItems: 'flex-start', flexWrap: 'wrap' }}>
      <Typography variant="caption" sx={{ color: 'text.secondary', minWidth: 48, pt: 0.1 }}>
        {label}
      </Typography>
      <Typography variant="caption" sx={{ fontFamily: 'IBM Plex Mono, monospace', color: 'rgba(0,212,255,0.85)', wordBreak: 'break-all' }}>
        {value}
      </Typography>
    </Box>
  );
}

function ArquivoResult({ result }) {
  const meta   = STATUS_META[result.vt_status] ?? STATUS_META.nao_analisado;
  const detecs = result.vt_relatorio?.deteccoes ?? {};

  return (
    <Paper sx={{ p: 3, borderRadius: 3, border: `1px solid ${meta.color}44`, background: `linear-gradient(135deg, rgba(0,0,0,0.6), ${meta.color}08)` }}>
      <Stack spacing={2}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, flexWrap: 'wrap' }}>
          <InsertDriveFileIcon sx={{ color: meta.color, fontSize: 28 }} />
          <Box sx={{ flex: 1, minWidth: 0 }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, wordBreak: 'break-all' }}>
              {result.nome_original}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              {fmt(result.tamanho_bytes)} • {result.mime_type || 'MIME desconhecido'} • {result.extensao_declarada || 'sem extensão'}
            </Typography>
          </Box>
          <Chip
            icon={meta.icon}
            label={meta.label}
            sx={{ bgcolor: `${meta.color}22`, color: meta.color, fontWeight: 700, border: `1px solid ${meta.color}55` }}
          />
        </Box>

        <DetectionBar detected={result.vt_total_detected} total={result.vt_total_engines} />

        <Box sx={{ p: 2, borderRadius: 2, bgcolor: 'rgba(0,0,0,0.3)' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mb: 1 }}>
            <FingerprintIcon sx={{ fontSize: 16, color: 'primary.main' }} />
            <Typography variant="caption" sx={{ color: 'primary.main', fontWeight: 600 }}>HASHES</Typography>
          </Box>
          <Stack spacing={0.5}>
            <HashRow label="MD5"     value={result.md5} />
            <HashRow label="SHA-1"   value={result.sha1} />
            <HashRow label="SHA-256" value={result.sha256} />
          </Stack>
        </Box>

        {Object.keys(detecs).length > 0 && (
          <Box>
            <Typography variant="caption" sx={{ color: '#ff1744', fontWeight: 600 }}>
              MOTORES QUE DETECTARAM ({Object.keys(detecs).length})
            </Typography>
            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 0.5 }}>
              {Object.entries(detecs).slice(0, 20).map(([engine, res]) => (
                <Chip key={engine} size="small"
                  label={`${engine}: ${res.result || '?'}`}
                  sx={{ bgcolor: 'rgba(255,23,68,0.12)', color: '#ff6090', fontSize: '0.65rem' }}
                />
              ))}
              {Object.keys(detecs).length > 20 && (
                <Chip size="small"
                  label={`+${Object.keys(detecs).length - 20} mais`}
                  sx={{ bgcolor: 'rgba(255,255,255,0.06)', color: 'text.secondary' }}
                />
              )}
            </Box>
          </Box>
        )}
      </Stack>
    </Paper>
  );
}

function URLResult({ result }) {
  const meta = STATUS_META[result.reputacao_status] ?? STATUS_META.desconhecida;
  const hops = result.redirect_hops ?? [];

  return (
    <Paper sx={{ p: 3, borderRadius: 3, border: `1px solid ${meta.color}44`, background: `linear-gradient(135deg, rgba(0,0,0,0.6), ${meta.color}08)` }}>
      <Stack spacing={2}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, flexWrap: 'wrap' }}>
          <LinkIcon sx={{ color: meta.color, fontSize: 28 }} />
          <Box sx={{ flex: 1, minWidth: 0 }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, wordBreak: 'break-all', fontFamily: 'IBM Plex Mono, monospace', fontSize: '0.85rem' }}>
              {result.url_original}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              Fonte: {result.reputacao_fonte ?? 'N/A'} •{' '}
              {result.via_tor
                ? <Box component="span" sx={{ color: '#ce93d8' }}><VpnLockIcon sx={{ fontSize: 12, mr: 0.3, verticalAlign: 'middle' }} />Via Tor</Box>
                : 'Sem Tor'}
            </Typography>
          </Box>
          <Chip
            icon={meta.icon}
            label={meta.label}
            sx={{ bgcolor: `${meta.color}22`, color: meta.color, fontWeight: 700, border: `1px solid ${meta.color}55` }}
          />
        </Box>

        <Box>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
            <Typography variant="body2" sx={{ color: meta.color, fontWeight: 700 }}>Status de Reputação</Typography>
            <Typography variant="body2" sx={{ color: meta.color, fontWeight: 700 }}>{meta.label}</Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={result.reputacao_status === 'maliciosa' ? 100 : result.reputacao_status === 'suspeita' ? 50 : 5}
            sx={{
              height: 10, borderRadius: 5,
              bgcolor: 'rgba(255,255,255,0.07)',
              '& .MuiLinearProgress-bar': { background: `linear-gradient(90deg, ${meta.color}, ${meta.color}99)`, borderRadius: 5 },
            }}
          />
        </Box>

        {result.url_final && result.url_final !== result.url_original && (
          <Box sx={{ p: 1.5, borderRadius: 2, bgcolor: 'rgba(0,212,255,0.05)', border: '1px solid rgba(0,212,255,0.15)' }}>
            <Typography variant="caption" color="text.secondary">URL Final</Typography>
            <Typography variant="body2" sx={{ fontFamily: 'IBM Plex Mono, monospace', color: 'primary.main', wordBreak: 'break-all', mt: 0.3 }}>
              {result.url_final}
            </Typography>
            {result.content_type_final && (
              <Typography variant="caption" color="text.secondary">Content-Type: {result.content_type_final}</Typography>
            )}
          </Box>
        )}

        {hops.length > 0 && (
          <Box>
            <Typography variant="caption" sx={{ color: 'primary.main', fontWeight: 600 }}>
              CADEIA DE REDIRECTS ({hops.length} hop{hops.length > 1 ? 's' : ''})
            </Typography>
            <List dense disablePadding sx={{ mt: 0.5 }}>
              {hops.map((hop, idx) => (
                <ListItem key={hop.ordem} disableGutters sx={{ alignItems: 'flex-start', pb: 0 }}>
                  <ListItemIcon sx={{ minWidth: 32, mt: 0.5 }}>
                    <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                      <Box sx={{
                        width: 24, height: 24, borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center',
                        bgcolor: hop.status_code >= 300 && hop.status_code < 400 ? 'rgba(255,214,0,0.15)' : 'rgba(0,212,255,0.12)',
                        border: `1px solid ${hop.status_code >= 300 && hop.status_code < 400 ? '#ffd600' : 'rgba(0,212,255,0.4)'}`,
                        fontSize: '0.6rem', fontWeight: 700,
                        color: hop.status_code >= 300 && hop.status_code < 400 ? '#ffd600' : 'primary.main',
                      }}>
                        {hop.ordem}
                      </Box>
                      {idx < hops.length - 1 && (
                        <Box sx={{ width: 1, flex: 1, bgcolor: 'rgba(255,255,255,0.08)', minHeight: 16, my: 0.3 }} />
                      )}
                    </Box>
                  </ListItemIcon>
                  <ListItemText
                    primary={
                      <Typography variant="caption" sx={{ fontFamily: 'IBM Plex Mono, monospace', wordBreak: 'break-all', color: 'text.primary' }}>
                        {hop.url}
                      </Typography>
                    }
                    secondary={
                      hop.status_code
                        ? <Typography variant="caption" sx={{ color: hop.status_code >= 400 ? '#ff1744' : 'text.secondary' }}>
                            HTTP {hop.status_code}
                            {hop.location && <> → <ArrowForwardIcon sx={{ fontSize: 10, verticalAlign: 'middle' }} /> {hop.location}</>}
                          </Typography>
                        : null
                    }
                  />
                </ListItem>
              ))}
            </List>
          </Box>
        )}

        {result.tor_erro && (
          <Alert severity="warning" sx={{ fontSize: '0.75rem' }}>Aviso Tor: {result.tor_erro}</Alert>
        )}
      </Stack>
    </Paper>
  );
}

function DropZone({ onFile, file, onClear }) {
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef();

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    setDragging(false);
    const f = e.dataTransfer.files?.[0];
    if (f) onFile(f);
  }, [onFile]);

  return (
    <Box
      onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
      onDragLeave={() => setDragging(false)}
      onDrop={handleDrop}
      onClick={() => !file && inputRef.current?.click()}
      sx={{
        border: `2px dashed ${dragging ? '#00d4ff' : 'rgba(0,212,255,0.25)'}`,
        borderRadius: 3, p: { xs: 3, sm: 5 }, textAlign: 'center',
        cursor: file ? 'default' : 'pointer', transition: 'all 0.2s',
        bgcolor: dragging ? 'rgba(0,212,255,0.06)' : 'rgba(0,212,255,0.02)',
        '&:hover': !file ? { borderColor: '#00d4ff', bgcolor: 'rgba(0,212,255,0.05)' } : {},
      }}
    >
      <input ref={inputRef} type="file" style={{ display: 'none' }} onChange={(e) => { const f = e.target.files?.[0]; if (f) onFile(f); }} />
      {!file ? (
        <Stack spacing={1} alignItems="center">
          <CloudUploadIcon sx={{ fontSize: 48, color: dragging ? '#00d4ff' : 'rgba(0,212,255,0.35)' }} />
          <Typography variant="h6" sx={{ fontWeight: 700 }}>Arraste o arquivo aqui</Typography>
          <Typography variant="body2" color="text.secondary">ou clique para selecionar • Máximo 32 MB</Typography>
        </Stack>
      ) : (
        <Stack direction="row" spacing={2} alignItems="center" justifyContent="center">
          <InsertDriveFileIcon sx={{ color: 'primary.main', fontSize: 32 }} />
          <Box sx={{ textAlign: 'left' }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{file.name}</Typography>
            <Typography variant="caption" color="text.secondary">{fmt(file.size)}</Typography>
          </Box>
          <Tooltip title="Remover arquivo">
            <IconButton size="small" onClick={(e) => { e.stopPropagation(); onClear(); }} sx={{ color: '#ff1744' }}>
              <DeleteIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        </Stack>
      )}
    </Box>
  );
}

export default function SandBox() {
  const [tab, setTab]               = useState(0);
  const [file, setFile]             = useState(null);
  const [fileResult, setFileResult] = useState(null);
  const [urlInput, setUrlInput]     = useState('');
  const [urlResult, setUrlResult]   = useState(null);
  const [loading, setLoading]       = useState(false);
  const [snack, setSnack]           = useState({ open: false, msg: '', sev: 'error' });

  const notify = (msg, sev = 'error') => setSnack({ open: true, msg, sev });
  const closeSnack = () => setSnack(s => ({ ...s, open: false }));

  const handleArquivoScan = async () => {
    if (!file) return notify('Selecione um arquivo primeiro.');
    setLoading(true);
    setFileResult(null);
    try {
      const form = new FormData();
      form.append('file', file);
      const res = await api.post('/sandbox/arquivo/', form, { headers: { 'Content-Type': 'multipart/form-data' } });
      setFileResult(res.data);
      notify('Análise concluída.', 'info');
    } catch (err) {
      notify(err.response?.data?.detail || err.message || 'Erro ao analisar arquivo.');
    } finally {
      setLoading(false);
    }
  };

  const handleURLScan = async () => {
    const url = urlInput.trim();
    if (!url) return notify('Digite uma URL primeiro.');
    if (!url.startsWith('http://') && !url.startsWith('https://'))
      return notify('A URL deve começar com http:// ou https://');
    setLoading(true);
    setUrlResult(null);
    try {
      const res = await api.post('/sandbox/url/', { url });
      setUrlResult(res.data);
      notify('Análise concluída.', 'info');
    } catch (err) {
      notify(err.response?.data?.detail || err.message || 'Erro ao analisar URL.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Container maxWidth="lg" sx={{ py: 5, px: { xs: 2, sm: 3 } }}>
      <Box sx={{ mb: 4 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 1 }}>
          <Box sx={{
            width: 44, height: 44, borderRadius: '12px', display: 'flex', alignItems: 'center', justifyContent: 'center',
            background: 'linear-gradient(135deg, rgba(255,23,68,0.2), rgba(255,109,0,0.08))',
            border: '1px solid rgba(255,23,68,0.3)',
          }}>
            <BugReportIcon sx={{ color: '#ff1744', fontSize: 22 }} />
          </Box>
          <Box>
            <Typography variant="h4" sx={{ fontWeight: 800, lineHeight: 1.1 }}>SandBox</Typography>
            <Typography variant="body2" color="text.secondary">Análise isolada de arquivos e URLs suspeitas</Typography>
          </Box>
        </Box>
      </Box>

      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 4 }}>
        <Tabs value={tab} onChange={(_, v) => setTab(v)} sx={{ '& .MuiTab-root': { minHeight: 48 } }}>
          <Tab icon={<InsertDriveFileIcon sx={{ fontSize: 18 }} />} iconPosition="start" label="Malware Scanner" />
          <Tab icon={<LinkIcon sx={{ fontSize: 18 }} />} iconPosition="start" label="URL Reputation" />
        </Tabs>
      </Box>

      {tab === 0 && (
        <Stack spacing={3}>
          <DropZone
            onFile={setFile}
            file={file}
            onClear={() => { setFile(null); setFileResult(null); }}
          />
          <Button
            variant="contained" size="large" fullWidth
            onClick={handleArquivoScan}
            disabled={!file || loading}
            startIcon={loading ? <CircularProgress size={18} color="inherit" /> : <BugReportIcon />}
            sx={{
              py: 1.5, fontWeight: 700,
              background: 'linear-gradient(135deg, #ff1744, #ff6d00)',
              '&:hover': { background: 'linear-gradient(135deg, #ff4569, #ff9100)' },
              '&:disabled': { opacity: 0.5 },
            }}
          >
            {loading ? 'Analisando…' : 'Escanear Arquivo'}
          </Button>
          {fileResult && <ArquivoResult result={fileResult} />}
        </Stack>
      )}

      {tab === 1 && (
        <Stack spacing={3}>
          <Box
            component="input"
            placeholder="https://exemplo.com/pagina-suspeita"
            value={urlInput}
            onChange={(e) => setUrlInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleURLScan()}
            sx={{
              width: '100%', p: '14px 18px',
              bgcolor: 'rgba(0,0,0,0.4)',
              border: '1px solid rgba(0,212,255,0.25)',
              borderRadius: 2, color: 'text.primary',
              fontFamily: 'IBM Plex Mono, monospace', fontSize: '0.875rem',
              outline: 'none', transition: 'border-color 0.2s', boxSizing: 'border-box',
              '&:focus': { borderColor: '#00d4ff' },
            }}
          />
          <Button
            variant="contained" size="large" fullWidth
            onClick={handleURLScan}
            disabled={!urlInput.trim() || loading}
            startIcon={loading ? <CircularProgress size={18} color="inherit" /> : <SendIcon />}
            sx={{
              py: 1.5, fontWeight: 700,
              background: 'linear-gradient(135deg, #6200ea, #00d4ff)',
              '&:hover': { background: 'linear-gradient(135deg, #7c4dff, #00e5ff)' },
              '&:disabled': { opacity: 0.5 },
            }}
          >
            {loading ? 'Analisando…' : 'Verificar URL'}
          </Button>
          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', p: 2, borderRadius: 2, bgcolor: 'rgba(0,0,0,0.25)', border: '1px solid rgba(255,255,255,0.06)' }}>
            <VpnLockIcon sx={{ fontSize: 16, color: '#ce93d8', mt: 0.1 }} />
            <Typography variant="caption" color="text.secondary">
              O rastreamento de redirects é feito via{' '}
              <Box component="span" sx={{ color: '#ce93d8' }}>proxy Tor</Box>. A reputação usa{' '}
              <Box component="span" sx={{ color: '#00d4ff' }}>Google Safe Browsing</Box> ou URLVoid como fallback.
            </Typography>
          </Box>
          {urlResult && <URLResult result={urlResult} />}
        </Stack>
      )}

      <Snackbar open={snack.open} autoHideDuration={5000} onClose={closeSnack} anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}>
        <Alert severity={snack.sev} variant="filled" onClose={closeSnack} sx={{ fontWeight: 600, borderRadius: 2 }}>
          {snack.msg}
        </Alert>
      </Snackbar>
    </Container>
  );
}
