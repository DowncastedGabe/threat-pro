import React, { useMemo, useState } from 'react';
import {
  Alert, Box, Button, Card, CardContent, Chip, Dialog, DialogContent,
  DialogTitle, Grid, IconButton, List, ListItem, ListItemIcon, ListItemText,
  MenuItem, Paper, Skeleton, Stack, Table, TableBody, TableCell,
  TableContainer, TableHead, TablePagination, TableRow, TextField,
  Typography, alpha,
} from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import DnsIcon from '@mui/icons-material/Dns';
import FolderOpenIcon from '@mui/icons-material/FolderOpen';
import GppBadIcon from '@mui/icons-material/GppBad';
import LanguageIcon from '@mui/icons-material/Language';
import LockIcon from '@mui/icons-material/Lock';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import RouterIcon from '@mui/icons-material/Router';
import ShieldIcon from '@mui/icons-material/Shield';
import { format, parseISO } from 'date-fns';

const RISK_META = {
  baixo: { label: 'Baixo', color: 'success', glow: '#00ff9d' },
  medio: { label: 'Medio', color: 'warning', glow: '#ffb830' },
  alto: { label: 'Alto', color: 'error', glow: '#ff6b3d' },
  critico: { label: 'Critico', color: 'error', glow: '#ff3b5c' },
};

function fmtDate(value) {
  try {
    return format(parseISO(value), 'dd/MM/yyyy HH:mm');
  } catch {
    return value || '-';
  }
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}

function riskFromScore(score = 0) {
  if (score >= 80) return 'critico';
  if (score >= 50) return 'alto';
  if (score >= 20) return 'medio';
  return 'baixo';
}

function RiskBadge({ score }) {
  const risco = riskFromScore(score);
  const meta = RISK_META[risco];
  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
      <Typography sx={{ fontWeight: 800, color: meta.glow }}>{score ?? 0}</Typography>
      <Chip
        label={meta.label.toUpperCase()}
        color={meta.color}
        size="small"
        sx={{ fontWeight: 800, boxShadow: `0 0 10px ${alpha(meta.glow, 0.22)}` }}
      />
    </Box>
  );
}

function DnsGrid({ registros }) {
  const data = asObject(registros);
  const registrosDns = asObject(data.registros || data);
  const entries = Object.entries(registrosDns);

  if (entries.length === 0) {
    return <Typography color="text.secondary">Nenhum registro DNS persistido.</Typography>;
  }

  return (
    <Grid container spacing={1.5}>
      {entries.map(([tipo, valores]) => (
        <Grid item xs={12} md={6} key={tipo}>
          <Box sx={{ p: 1.5, borderRadius: 1, border: '1px solid rgba(255,255,255,0.08)' }}>
            <Typography variant="caption" sx={{ color: 'primary.main', fontWeight: 800 }}>
              {tipo.toUpperCase()}
            </Typography>
            <Stack spacing={0.6} sx={{ mt: 1 }}>
              {asArray(valores).length > 0 ? asArray(valores).map((valor, index) => (
                <Typography
                  key={`${tipo}-${index}`}
                  variant="body2"
                  sx={{ fontFamily: '"JetBrains Mono", monospace', wordBreak: 'break-all' }}
                >
                  {String(valor)}
                </Typography>
              )) : (
                <Typography variant="body2" color="text.secondary">Sem registros</Typography>
              )}
            </Stack>
          </Box>
        </Grid>
      ))}
    </Grid>
  );
}

function TlsCard({ tls }) {
  const data = asObject(tls);
  const valido = Boolean(data.valido);
  const dias = data.dias_restantes;

  return (
    <Card sx={{ height: '100%', border: `1px solid ${alpha(valido ? '#00ff9d' : '#ff3b5c', 0.18)}` }}>
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
          <LockIcon color={valido ? 'success' : 'error'} />
          <Typography variant="h6">Certificado TLS</Typography>
        </Box>
        <Stack spacing={1}>
          <Chip
            label={valido ? 'Valido' : 'Invalido ou indisponivel'}
            color={valido ? 'success' : 'error'}
            sx={{ alignSelf: 'flex-start', fontWeight: 800 }}
          />
          <Typography variant="body2" color="text.secondary">Emissor: {data.issuer_common_name || '-'}</Typography>
          <Typography variant="body2" color="text.secondary">Expira em: {data.expira_em || '-'}</Typography>
          <Typography variant="body2" color="text.secondary">Dias restantes: {dias ?? '-'}</Typography>
          <Typography variant="body2" color="text.secondary">Common Name: {data.common_name || '-'}</Typography>
        </Stack>
      </CardContent>
    </Card>
  );
}

function InfraCard({ infra }) {
  const itens = asArray(asObject(infra).itens);
  const online = itens.filter((item) => item.status === 'Online').length;
  const offline = itens.filter((item) => item.status === 'Offline').length;

  return (
    <Card sx={{ height: '100%', border: '1px solid rgba(0,212,255,0.14)' }}>
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
          <RouterIcon color="primary" />
          <Typography variant="h6">Infra SPF</Typography>
        </Box>
        <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mb: 2 }}>
          <Chip label={`${online} online`} color="success" size="small" sx={{ fontWeight: 700 }} />
          <Chip label={`${offline} offline`} color="error" size="small" sx={{ fontWeight: 700 }} />
          <Chip label={`${itens.length} alvos`} size="small" sx={{ fontWeight: 700 }} />
        </Box>
        <Stack spacing={1}>
          {itens.length === 0 ? (
            <Typography color="text.secondary">Nenhum alvo SPF persistido.</Typography>
          ) : itens.map((item, index) => {
            const color = item.status === 'Online' ? 'success' : item.status === 'Offline' ? 'error' : 'default';
            const alvo = item.ip_testado || item.valor || '-';
            const label = item.servico ? `${item.servico} - ${alvo}` : alvo;
            return (
              <Box key={`${item.valor}-${index}`} sx={{ display: 'flex', justifyContent: 'space-between', gap: 1 }}>
                <Typography variant="body2" sx={{ fontFamily: '"JetBrains Mono", monospace', wordBreak: 'break-all' }}>
                  {label}
                </Typography>
                <Chip label={item.status || 'Inconclusivo'} color={color} size="small" />
              </Box>
            );
          })}
        </Stack>
      </CardContent>
    </Card>
  );
}

function ExposureAlert({ diretorios }) {
  const data = asObject(diretorios);
  const brute = asArray(data.bruteforce);
  const dorks = asArray(data.dorks);
  const total = brute.length + dorks.length;

  if (total === 0) {
    return (
      <Alert severity="success" icon={<ShieldIcon />}>
        Nenhum diretorio exposto ou vazamento indexado foi persistido para este dominio.
      </Alert>
    );
  }

  return (
    <Stack spacing={2}>
      {brute.length > 0 && (
        <Alert severity="error" icon={<FolderOpenIcon />} sx={{ borderRadius: 1 }}>
          <Typography variant="subtitle2" sx={{ fontWeight: 800, mb: 1 }}>
            Diretorios expostos ({brute.length})
          </Typography>
          <List dense disablePadding>
            {brute.map((item, index) => (
              <ListItem key={`brute-${index}`} disableGutters>
                <ListItemIcon sx={{ minWidth: 30 }}><GppBadIcon color="error" fontSize="small" /></ListItemIcon>
                <ListItemText
                  primary={item.url || item.path || '-'}
                  secondary={[item.status, item.observacao].filter(Boolean).join(' - ')}
                  primaryTypographyProps={{ sx: { fontFamily: '"JetBrains Mono", monospace', wordBreak: 'break-all' } }}
                />
              </ListItem>
            ))}
          </List>
        </Alert>
      )}
      {dorks.length > 0 && (
        <Alert severity="warning" icon={<LanguageIcon />} sx={{ borderRadius: 1 }}>
          <Typography variant="subtitle2" sx={{ fontWeight: 800, mb: 1 }}>
            Vazamentos indexados ({dorks.length})
          </Typography>
          <List dense disablePadding>
            {dorks.map((item, index) => (
              <ListItem key={`dork-${index}`} disableGutters>
                <ListItemText
                  primary={item.url || '-'}
                  secondary={item.titulo || item.snippet}
                  primaryTypographyProps={{ sx: { wordBreak: 'break-all' } }}
                />
              </ListItem>
            ))}
          </List>
        </Alert>
      )}
    </Stack>
  );
}

function SiteDetailsDialog({ row, onClose }) {
  if (!row) return null;

  const registrosDns = row.registros_dns || row.dns_records || {};
  const infraHealth = row.infra_health || row.infra_status || {};
  const risco = riskFromScore(row.risco_score || 0);
  const meta = RISK_META[risco];

  return (
    <Dialog fullScreen open={Boolean(row)} onClose={onClose}>
      <DialogTitle sx={{ borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', gap: 2, alignItems: 'center' }}>
          <Box>
            <Typography variant="h5" sx={{ fontWeight: 800 }}>{row.dominio}</Typography>
            <Typography variant="body2" color="text.secondary">
              {row.url} {row.ip_alvo ? `| IP alvo: ${row.ip_alvo}` : ''}
            </Typography>
          </Box>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Chip label={`Score ${row.risco_score || 0}`} color={meta.color} sx={{ fontWeight: 800 }} />
            <IconButton onClick={onClose}><CloseIcon /></IconButton>
          </Box>
        </Box>
      </DialogTitle>
      <DialogContent sx={{ p: { xs: 2, md: 3 } }}>
        <Stack spacing={3}>
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}><TlsCard tls={row.certificados_tls} /></Grid>
            <Grid item xs={12} md={6}><InfraCard infra={infraHealth} /></Grid>
          </Grid>

          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                <DnsIcon color="primary" />
                <Typography variant="h6">DNS Grid</Typography>
              </Box>
              <DnsGrid registros={registrosDns} />
            </CardContent>
          </Card>

          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                <FolderOpenIcon color="error" />
                <Typography variant="h6">Vulnerability Alert</Typography>
              </Box>
              <ExposureAlert diretorios={row.diretorios_expostos} />
            </CardContent>
          </Card>
        </Stack>
      </DialogContent>
    </Dialog>
  );
}

export function SiteHistoryTableSkeleton() {
  return (
    <Card>
      <CardContent sx={{ p: 3 }}>
        <Skeleton variant="text" width={240} height={28} sx={{ mb: 2 }} />
        {[...Array(6)].map((_, i) => (
          <Skeleton key={i} variant="rectangular" height={52} sx={{ mb: 1, borderRadius: 1 }} />
        ))}
      </CardContent>
    </Card>
  );
}

export default function SiteHistoryTable({ historico, onFilterChange }) {
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  const [selectedRow, setSelectedRow] = useState(null);
  const [dominio, setDominio] = useState('');
  const [risco, setRisco] = useState('');

  const rows = useMemo(() => asArray(historico), [historico]);
  const paginated = rows.slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage);

  const applyFilters = () => {
    setPage(0);
    onFilterChange?.({ dominio: dominio.trim() || undefined, risco: risco || undefined });
  };

  const clearFilters = () => {
    setDominio('');
    setRisco('');
    setPage(0);
    onFilterChange?.({});
  };

  return (
    <>
      <Card>
        <CardContent sx={{ p: { xs: 2, sm: 3 } }}>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2.5, gap: 2 }}>
            <Typography variant="h6">Registro de Analises de Sites</Typography>
            <Chip
              label={`${rows.length} registros carregados`}
              size="small"
              sx={{ backgroundColor: alpha('#00d4ff', 0.1), color: 'primary.main', border: '1px solid', borderColor: alpha('#00d4ff', 0.25) }}
            />
          </Box>

          <Box sx={{ display: 'flex', gap: 1.5, mb: 2.5, flexWrap: 'wrap' }}>
            <TextField
              size="small"
              label="Filtrar dominio"
              value={dominio}
              onChange={(event) => setDominio(event.target.value)}
              sx={{ minWidth: { xs: '100%', sm: 260 } }}
            />
            <TextField
              select
              size="small"
              label="Risco"
              value={risco}
              onChange={(event) => setRisco(event.target.value)}
              sx={{ minWidth: 160 }}
            >
              <MenuItem value="">Todos</MenuItem>
              <MenuItem value="baixo">Baixo</MenuItem>
              <MenuItem value="medio">Medio</MenuItem>
              <MenuItem value="alto">Alto</MenuItem>
              <MenuItem value="critico">Critico</MenuItem>
            </TextField>
            <Button variant="contained" onClick={applyFilters}>Aplicar</Button>
            <Button variant="outlined" onClick={clearFilters}>Limpar</Button>
          </Box>

          <TableContainer component={Paper} elevation={0} sx={{ backgroundColor: 'transparent', borderRadius: 1, border: '1px solid rgba(255,255,255,0.06)' }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ backgroundColor: '#0d1421' }}>Dominio</TableCell>
                  <TableCell sx={{ backgroundColor: '#0d1421' }}>IP alvo</TableCell>
                  <TableCell sx={{ backgroundColor: '#0d1421' }}>Risco</TableCell>
                  <TableCell sx={{ backgroundColor: '#0d1421' }}>Data/Hora</TableCell>
                  <TableCell sx={{ backgroundColor: '#0d1421', width: 140 }} />
                </TableRow>
              </TableHead>
              <TableBody>
                {paginated.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5} sx={{ textAlign: 'center', py: 6, color: 'text.secondary', border: 0 }}>
                      Nenhum registro de site encontrado.
                    </TableCell>
                  </TableRow>
                ) : paginated.map((row) => (
                  <TableRow key={row.id} hover>
                    <TableCell>
                      <Typography sx={{ fontFamily: '"JetBrains Mono", monospace', fontWeight: 700, color: 'primary.light' }}>
                        {row.dominio || '-'}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">{row.url}</Typography>
                    </TableCell>
                    <TableCell sx={{ fontFamily: '"JetBrains Mono", monospace', color: 'text.secondary' }}>
                      {row.ip_alvo || '-'}
                    </TableCell>
                    <TableCell><RiskBadge score={row.risco_score || 0} /></TableCell>
                    <TableCell sx={{ color: 'text.secondary', fontFamily: '"JetBrains Mono", monospace' }}>
                      {fmtDate(row.timestamp || row.timestamp_auditoria)}
                    </TableCell>
                    <TableCell>
                      <Button
                        variant="outlined"
                        size="small"
                        endIcon={<OpenInNewIcon sx={{ fontSize: 14 }} />}
                        onClick={() => setSelectedRow(row)}
                      >
                        Detalhes
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <TablePagination
            component="div"
            count={rows.length}
            page={page}
            onPageChange={(_, p) => setPage(p)}
            rowsPerPage={rowsPerPage}
            onRowsPerPageChange={(event) => {
              setRowsPerPage(parseInt(event.target.value, 10));
              setPage(0);
            }}
            rowsPerPageOptions={[5, 10, 25, 50]}
            labelRowsPerPage="Linhas:"
            labelDisplayedRows={({ from, to, count }) => `${from}-${to} de ${count}`}
            sx={{ borderTop: '1px solid rgba(255,255,255,0.04)', color: 'text.secondary' }}
          />
        </CardContent>
      </Card>

      <SiteDetailsDialog row={selectedRow} onClose={() => setSelectedRow(null)} />
    </>
  );
}
