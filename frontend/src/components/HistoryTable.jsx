import React, { useState, useMemo } from 'react';
import {
  Card, CardContent, Typography, Box, Chip, Button, Drawer, IconButton,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  TablePagination, TableSortLabel, Paper, Skeleton, alpha, Tabs, Tab,
  Divider,
} from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import BugReportIcon from '@mui/icons-material/BugReport';
import TimelineIcon from '@mui/icons-material/Timeline';
import InfoIcon from '@mui/icons-material/Info';
import { format, parseISO } from 'date-fns';
import CveList from './CveList';
import IpTimeline from './IpTimeline';

const RISK_COLOR = {
  critico:     'error',
  alto:        'warning',
  medio:       'info',
  baixo:       'success',
  desconhecido:'default',
  agendado:    'default',
};

const RISK_GLOW = {
  critico:     '#ff3b5c',
  alto:        '#ffb830',
  medio:       '#00d4ff',
  baixo:       '#00ff9d',
  desconhecido:'#8e8e93',
  agendado:    '#00d4ff',
};

function descendingComparator(a, b, orderBy) {
  const av = a[orderBy] ?? '';
  const bv = b[orderBy] ?? '';
  if (bv < av) return -1;
  if (bv > av) return 1;
  return 0;
}

function getComparator(order, orderBy) {
  return order === 'desc'
    ? (a, b) => descendingComparator(a, b, orderBy)
    : (a, b) => -descendingComparator(a, b, orderBy);
}

const COLUMNS = [
  { id: 'id',                  label: 'ID',        sortable: true,  width: 70  },
  { id: 'ip',                  label: 'Alvo (IP)',  sortable: true,  width: 150 },
  { id: 'risco',               label: 'Risco',      sortable: true,  width: 120 },
  { id: 'score',               label: 'Score',      sortable: true,  width: 90  },
  { id: 'pais',                label: 'País',       sortable: true,  width: 130 },
  { id: 'timestamp_auditoria', label: 'Data/Hora',  sortable: true,  width: 185 },
  { id: 'actions',             label: '',           sortable: false, width: 120 },
];

export function HistoryTableSkeleton() {
  return (
    <Card>
      <CardContent sx={{ p: 3 }}>
        <Skeleton variant="text" width={200} height={28} sx={{ mb: 2 }} />
        {[...Array(6)].map((_, i) => (
          <Skeleton key={i} variant="rectangular" height={48} sx={{ mb: 1, borderRadius: 1 }} />
        ))}
      </CardContent>
    </Card>
  );
}

/* ── Drawer de Detalhes com Abas ─────────────────────────────────────────── */
function DrawerDetalhes({ row, onClose }) {
  const [aba, setAba] = useState(0);

  if (!row) return null;
  const risco     = (row.risco || 'desconhecido').toLowerCase();
  const glow      = RISK_GLOW[risco] || '#8e8e93';
  const vulns     = row.vulnerabilidades || {};
  const cves      = vulns.cves || [];
  const temCves   = cves.length > 0;

  const fmtDate = (val) => {
    try { return format(parseISO(val), 'dd/MM/yyyy HH:mm'); } catch { return val ?? '—'; }
  };

  return (
    <Box sx={{ width: { xs: '100vw', sm: 460 }, height: '100%', display: 'flex', flexDirection: 'column' }}>
      {/* Header */}
      <Box sx={{ p: 3, pb: 0 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
          <Typography variant="h6" sx={{ fontWeight: 700 }}>Relatório de Análise</Typography>
          <IconButton onClick={onClose} size="small"><CloseIcon /></IconButton>
        </Box>

        {/* IP Hero */}
        <Box sx={{
          p: 2.5, mb: 2, borderRadius: 2,
          background: `linear-gradient(135deg, ${alpha(glow, 0.12)}, transparent)`,
          border: `1px solid ${alpha(glow, 0.25)}`,
        }}>
          <Typography variant="caption" color="text.secondary">IP Analisado</Typography>
          <Typography variant="h5" sx={{ fontFamily: '"JetBrains Mono", monospace', fontWeight: 700, mt: 0.5 }}>
            {row.ip}
          </Typography>
          <Box sx={{ display: 'flex', gap: 1, mt: 1.5, flexWrap: 'wrap' }}>
            <Chip label={risco.toUpperCase()} color={RISK_COLOR[risco]} size="small" sx={{ fontWeight: 700 }} />
            <Chip
              label={`Score: ${row.score ?? '—'}`} size="small"
              sx={{ backgroundColor: alpha(glow, 0.1), color: glow, border: `1px solid ${alpha(glow, 0.3)}` }}
            />
            {temCves && (
              <Chip
                icon={<BugReportIcon sx={{ fontSize: '0.85rem !important' }} />}
                label={`${cves.length} CVE${cves.length !== 1 ? 's' : ''}`}
                size="small"
                sx={{ backgroundColor: alpha('#ff3b5c', 0.1), color: '#ff3b5c', border: '1px solid rgba(255,59,92,0.3)' }}
              />
            )}
          </Box>
        </Box>

        {/* Abas */}
        <Tabs
          value={aba}
          onChange={(_, v) => setAba(v)}
          sx={{
            mb: 0,
            '& .MuiTab-root': { minHeight: 40, fontSize: '0.78rem', py: 0 },
            '& .MuiTabs-indicator': { backgroundColor: glow },
          }}
        >
          <Tab icon={<InfoIcon sx={{ fontSize: 16 }} />} iconPosition="start" label="Detalhes" />
          <Tab
            icon={<BugReportIcon sx={{ fontSize: 16 }} />}
            iconPosition="start"
            label={`CVEs${temCves ? ` (${cves.length})` : ''}`}
          />
          <Tab icon={<TimelineIcon sx={{ fontSize: 16 }} />} iconPosition="start" label="Timeline" />
        </Tabs>
        <Divider sx={{ borderColor: 'rgba(255,255,255,0.05)' }} />
      </Box>

      {/* Conteúdo das abas */}
      <Box sx={{ flex: 1, overflowY: 'auto', p: 3, pt: 2 }}>
        {/* Aba 0: Detalhes */}
        {aba === 0 && (
          <Box>
            {[
              { label: 'ID da Análise',    value: `#${row.id}` },
              { label: 'País de Origem',   value: row.pais || 'Desconhecido' },
              { label: 'Latitude',         value: row.latitude  ? row.latitude.toFixed(4)  : '—' },
              { label: 'Longitude',        value: row.longitude ? row.longitude.toFixed(4) : '—' },
              { label: 'Data da Auditoria',value: fmtDate(row.timestamp_auditoria) },
            ].map(({ label, value }) => (
              <Box key={label} sx={{ mb: 2.5, pb: 2.5, borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                <Typography variant="caption" color="text.secondary">{label}</Typography>
                <Typography variant="body2" sx={{ fontWeight: 600, mt: 0.5 }}>{value}</Typography>
              </Box>
            ))}

            {/* Info Shodan básica */}
            {vulns.org && (
              <Box sx={{ p: 1.5, borderRadius: 2, backgroundColor: alpha('#00d4ff', 0.04), border: '1px solid rgba(0,212,255,0.1)' }}>
                <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 0.5 }}>Shodan — Organização</Typography>
                <Typography variant="body2" sx={{ fontWeight: 600 }}>{vulns.org}</Typography>
                {vulns.portas?.length > 0 && (
                  <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 0.5 }}>
                    Portas indexadas: {vulns.portas.join(', ')}
                  </Typography>
                )}
              </Box>
            )}
          </Box>
        )}

        {/* Aba 1: CVEs */}
        {aba === 1 && (
          <CveList
            shodan={
              row.vulnerabilidades
                ? {
                    cves: row.vulnerabilidades.cves || [],
                    org: row.vulnerabilidades.org,
                    disponivel: true,
                  }
                : { disponivel: false }
            }
          />
        )}

        {/* Aba 2: Timeline */}
        {aba === 2 && <IpTimeline ip={row.ip} />}
      </Box>
    </Box>
  );
}

/* ── Tabela principal ────────────────────────────────────────────────────── */
export default function HistoryTable({ historico }) {
  const [order, setOrder]             = useState('desc');
  const [orderBy, setOrderBy]         = useState('timestamp_auditoria');
  const [page, setPage]               = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  const [selectedRow, setSelectedRow] = useState(null);

  const handleSort = (col) => {
    if (orderBy === col) {
      setOrder(prev => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setOrderBy(col);
      setOrder('desc');
    }
    setPage(0);
  };

  const sorted    = useMemo(() => [...historico].sort(getComparator(order, orderBy)), [historico, order, orderBy]);
  const paginated = sorted.slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage);
  const fmtDate   = (val) => { try { return format(parseISO(val), 'dd/MM/yyyy HH:mm'); } catch { return val ?? '—'; } };

  return (
    <>
      <Card>
        <CardContent sx={{ p: { xs: 2, sm: 3 } }}>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2.5 }}>
            <Typography variant="h6">Registro de Análises de IP</Typography>
            <Chip
              label={`${historico.length} registros`}
              size="small"
              sx={{ backgroundColor: alpha('#00d4ff', 0.1), color: 'primary.main', borderColor: alpha('#00d4ff', 0.25), border: '1px solid' }}
            />
          </Box>

          <TableContainer component={Paper} elevation={0}
            sx={{ backgroundColor: 'transparent', borderRadius: 2, border: '1px solid rgba(255,255,255,0.05)' }}>
            <Table size="small" stickyHeader>
              <TableHead>
                <TableRow>
                  {COLUMNS.map(col => (
                    <TableCell
                      key={col.id}
                      sortDirection={orderBy === col.id ? order : false}
                      sx={{ width: col.width, backgroundColor: '#0d1421' }}
                    >
                      {col.sortable ? (
                        <TableSortLabel
                          active={orderBy === col.id}
                          direction={orderBy === col.id ? order : 'asc'}
                          onClick={() => handleSort(col.id)}
                          sx={{ '&.Mui-active': { color: 'primary.main' }, '&.Mui-active .MuiTableSortLabel-icon': { color: 'primary.main' } }}
                        >
                          {col.label}
                        </TableSortLabel>
                      ) : col.label}
                    </TableCell>
                  ))}
                </TableRow>
              </TableHead>
              <TableBody>
                {paginated.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={COLUMNS.length} sx={{ textAlign: 'center', py: 6, color: 'text.secondary', border: 0 }}>
                      Nenhum registro encontrado.
                    </TableCell>
                  </TableRow>
                ) : paginated.map((row) => {
                  const risco  = (row.risco || 'desconhecido').toLowerCase();
                  const cves   = row.vulnerabilidades?.cves || [];
                  const temCves = cves.length > 0;
                  return (
                    <TableRow key={row.id} hover>
                      <TableCell sx={{ color: 'text.secondary', fontSize: '0.78rem' }}>{row.id}</TableCell>
                      <TableCell>
                        <Typography sx={{ fontFamily: '"JetBrains Mono", monospace', fontWeight: 600, fontSize: '0.82rem', color: 'primary.light' }}>
                          {row.ip}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={risco.toUpperCase()} color={RISK_COLOR[risco]} size="small"
                          sx={{ fontWeight: 700, fontSize: '0.68rem', boxShadow: `0 0 8px ${alpha(RISK_GLOW[risco] || '#fff', 0.25)}` }}
                        />
                      </TableCell>
                      <TableCell>
                        <Typography sx={{ fontWeight: 700, color: RISK_GLOW[risco], fontSize: '0.88rem' }}>
                          {row.score ?? '—'}
                        </Typography>
                      </TableCell>
                      <TableCell sx={{ color: 'text.secondary', fontSize: '0.85rem' }}>
                        {row.pais || '—'}
                      </TableCell>
                      <TableCell sx={{ color: 'text.secondary', fontSize: '0.8rem', fontFamily: '"JetBrains Mono", monospace' }}>
                        {fmtDate(row.timestamp_auditoria)}
                      </TableCell>
                      <TableCell>
                        <Box sx={{ display: 'flex', gap: 0.5, alignItems: 'center' }}>
                          {temCves && (
                            <Chip
                              icon={<BugReportIcon sx={{ fontSize: '0.8rem !important' }} />}
                              label={cves.length}
                              size="small"
                              sx={{ height: 20, fontSize: '0.65rem', backgroundColor: alpha('#ff3b5c', 0.1), color: '#ff3b5c' }}
                            />
                          )}
                          <Button
                            variant="outlined" size="small"
                            endIcon={<OpenInNewIcon sx={{ fontSize: 14 }} />}
                            onClick={() => setSelectedRow(row)}
                            sx={{ fontSize: '0.72rem', py: 0.4, px: 1.2, borderRadius: '8px' }}
                          >
                            Relatório
                          </Button>
                        </Box>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </TableContainer>

          <TablePagination
            component="div"
            count={historico.length}
            page={page}
            onPageChange={(_, p) => setPage(p)}
            rowsPerPage={rowsPerPage}
            onRowsPerPageChange={(e) => { setRowsPerPage(parseInt(e.target.value, 10)); setPage(0); }}
            rowsPerPageOptions={[5, 10, 25, 50]}
            labelRowsPerPage="Linhas:"
            labelDisplayedRows={({ from, to, count }) => `${from}–${to} de ${count}`}
            sx={{ borderTop: '1px solid rgba(255,255,255,0.04)', color: 'text.secondary' }}
          />
        </CardContent>
      </Card>

      <Drawer anchor="right" open={Boolean(selectedRow)} onClose={() => setSelectedRow(null)}>
        <DrawerDetalhes row={selectedRow} onClose={() => setSelectedRow(null)} />
      </Drawer>
    </>
  );
}
