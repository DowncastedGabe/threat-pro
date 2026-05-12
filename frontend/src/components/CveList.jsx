/**
 * CveList.jsx — Cards de Vulnerabilidades do Shodan
 *
 * Escala de cores CVSS (padrão NVD):
 *  Crítico  (9.0–10.0) → #ff3b5c  vermelho
 *  Alto     (7.0–8.9)  → #ff6b35  laranja
 *  Médio    (4.0–6.9)  → #ffb830  amarelo
 *  Baixo    (0.1–3.9)  → #00ff9d  verde
 *  N/A                 → #6e6e8a  cinza
 */

import React, { useState, useMemo } from 'react';
import {
  Box, Typography, Chip, Stack, alpha, Collapse, Button,
  Tooltip, IconButton, Link,
} from '@mui/material';
import BugReportIcon        from '@mui/icons-material/BugReport';
import OpenInNewIcon        from '@mui/icons-material/OpenInNew';
import ExpandMoreIcon       from '@mui/icons-material/ExpandMore';
import ExpandLessIcon       from '@mui/icons-material/ExpandLess';
import ShieldIcon           from '@mui/icons-material/Shield';

/* ── Configuração de severidade ──────────────────────────────────────────── */

function getSeveridadeConfig(cvss) {
  if (cvss === null || cvss === undefined) {
    return { label: 'N/A', color: '#6e6e8a', bgAlpha: 0.06 };
  }
  if (cvss >= 9.0) return { label: 'CRÍTICO',  color: '#ff3b5c', bgAlpha: 0.08 };
  if (cvss >= 7.0) return { label: 'ALTO',     color: '#ff6b35', bgAlpha: 0.07 };
  if (cvss >= 4.0) return { label: 'MÉDIO',    color: '#ffb830', bgAlpha: 0.07 };
  return           { label: 'BAIXO',    color: '#00ff9d', bgAlpha: 0.05 };
}

/* ── Card individual de CVE ──────────────────────────────────────────────── */
function CveCard({ cve }) {
  const [expandido, setExpandido] = useState(false);
  const cfg = getSeveridadeConfig(cve.cvss);
  const nvdUrl = `https://nvd.nist.gov/vuln/detail/${cve.cve_id}`;
  const temSummary = cve.summary && cve.summary.trim().length > 0;

  return (
    <Box
      sx={{
        p: 1.5,
        borderRadius: 2,
        border: `1px solid ${alpha(cfg.color, 0.2)}`,
        backgroundColor: alpha(cfg.color, cfg.bgAlpha),
        transition: 'border-color 0.2s',
        '&:hover': { borderColor: alpha(cfg.color, 0.4) },
      }}
    >
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
        {/* CVE ID */}
        <Typography
          variant="body2"
          sx={{
            fontFamily: '"JetBrains Mono", monospace',
            fontWeight: 700,
            color: cfg.color,
            fontSize: '0.82rem',
            flex: 1,
          }}
        >
          {cve.cve_id}
        </Typography>

        {/* CVSS Score */}
        {cve.cvss !== null && cve.cvss !== undefined && (
          <Chip
            label={`CVSS ${cve.cvss.toFixed(1)}`}
            size="small"
            sx={{
              fontWeight: 800,
              fontSize: '0.68rem',
              backgroundColor: alpha(cfg.color, 0.15),
              color: cfg.color,
              border: `1px solid ${alpha(cfg.color, 0.3)}`,
            }}
          />
        )}

        {/* Severidade */}
        <Chip
          label={cfg.label}
          size="small"
          sx={{
            fontWeight: 700,
            fontSize: '0.65rem',
            backgroundColor: alpha(cfg.color, 0.12),
            color: cfg.color,
          }}
        />

        {/* Link NVD */}
        <Tooltip title="Ver no NVD (NIST)">
          <IconButton
            size="small"
            component={Link}
            href={nvdUrl}
            target="_blank"
            rel="noopener noreferrer"
            sx={{ color: 'text.disabled', p: 0.3, '&:hover': { color: cfg.color } }}
          >
            <OpenInNewIcon sx={{ fontSize: 14 }} />
          </IconButton>
        </Tooltip>

        {/* Expand summary */}
        {temSummary && (
          <IconButton
            size="small"
            onClick={() => setExpandido(!expandido)}
            sx={{ color: 'text.disabled', p: 0.3 }}
          >
            {expandido ? <ExpandLessIcon sx={{ fontSize: 16 }} /> : <ExpandMoreIcon sx={{ fontSize: 16 }} />}
          </IconButton>
        )}
      </Box>

      {temSummary && (
        <Collapse in={expandido}>
          <Typography
            variant="caption"
            color="text.secondary"
            sx={{ display: 'block', mt: 1, lineHeight: 1.6, fontSize: '0.74rem' }}
          >
            {cve.summary}
          </Typography>
        </Collapse>
      )}
    </Box>
  );
}

/* ── Componente principal ────────────────────────────────────────────────── */
export default function CveList({ shodan }) {
  const [mostrarTodos, setMostrarTodos] = useState(false);
  const LIMITE_INICIAL = 5;

  // Ordena por CVSS decrescente (críticos no topo)
  const cvesOrdenados = useMemo(() => {
    if (!shodan?.cves) return [];
    return [...shodan.cves].sort((a, b) => (b.cvss ?? 0) - (a.cvss ?? 0));
  }, [shodan]);

  const cvesExibidos = mostrarTodos ? cvesOrdenados : cvesOrdenados.slice(0, LIMITE_INICIAL);

  const totalCritico = cvesOrdenados.filter(c => c.cvss >= 9.0).length;
  const totalAlto    = cvesOrdenados.filter(c => c.cvss >= 7.0 && c.cvss < 9.0).length;

  // Sem dados Shodan
  if (!shodan || !shodan.disponivel) {
    return (
      <Box sx={{
        p: 2, borderRadius: 2, textAlign: 'center',
        border: '1px dashed rgba(255,255,255,0.08)',
        backgroundColor: 'rgba(255,255,255,0.02)',
      }}>
        <ShieldIcon sx={{ fontSize: 36, color: alpha('#fff', 0.1), mb: 1 }} />
        <Typography variant="body2" color="text.disabled">
          Shodan não configurado.
        </Typography>
        <Typography variant="caption" color="text.disabled">
          Adicione SHODAN_API_KEY no .env para habilitar CVEs.
        </Typography>
      </Box>
    );
  }

  if (cvesOrdenados.length === 0) {
    return (
      <Box sx={{
        display: 'flex', alignItems: 'center', gap: 1.5, p: 2,
        borderRadius: 2, backgroundColor: alpha('#00ff9d', 0.04),
        border: '1px solid rgba(0,255,157,0.1)',
      }}>
        <ShieldIcon sx={{ color: '#00ff9d', fontSize: 20 }} />
        <Box>
          <Typography variant="body2" sx={{ fontWeight: 600, color: '#00ff9d' }}>
            Nenhuma CVE Detectada
          </Typography>
          <Typography variant="caption" color="text.secondary">
            {shodan.erro
              ? shodan.erro
              : 'IP não possui vulnerabilidades conhecidas no Shodan.'}
          </Typography>
        </Box>
      </Box>
    );
  }

  return (
    <Box>
      {/* Resumo de severidade */}
      <Box sx={{ display: 'flex', gap: 1, mb: 2, flexWrap: 'wrap', alignItems: 'center' }}>
        <BugReportIcon sx={{ color: '#ff3b5c', fontSize: 20 }} />
        <Typography variant="subtitle2" sx={{ fontWeight: 700, color: '#ff3b5c' }}>
          {cvesOrdenados.length} CVE{cvesOrdenados.length !== 1 ? 's' : ''} encontrada{cvesOrdenados.length !== 1 ? 's' : ''}
        </Typography>
        {totalCritico > 0 && (
          <Chip label={`${totalCritico} crítica${totalCritico !== 1 ? 's' : ''}`} size="small"
            sx={{ fontWeight: 700, fontSize: '0.68rem', backgroundColor: alpha('#ff3b5c', 0.12), color: '#ff3b5c' }} />
        )}
        {totalAlto > 0 && (
          <Chip label={`${totalAlto} alta${totalAlto !== 1 ? 's' : ''}`} size="small"
            sx={{ fontWeight: 700, fontSize: '0.68rem', backgroundColor: alpha('#ff6b35', 0.12), color: '#ff6b35' }} />
        )}
        {shodan.org && (
          <Chip label={shodan.org} size="small" variant="outlined"
            sx={{ fontSize: '0.7rem', borderColor: 'rgba(255,255,255,0.1)', color: 'text.secondary', ml: 'auto' }} />
        )}
      </Box>

      {/* Lista de CVEs */}
      <Stack spacing={1}>
        {cvesExibidos.map((cve) => (
          <CveCard key={cve.cve_id} cve={cve} />
        ))}
      </Stack>

      {/* Botão ver mais */}
      {cvesOrdenados.length > LIMITE_INICIAL && (
        <Button
          size="small"
          onClick={() => setMostrarTodos(!mostrarTodos)}
          sx={{ mt: 1.5, color: 'text.secondary', fontSize: '0.75rem' }}
          endIcon={mostrarTodos ? <ExpandLessIcon /> : <ExpandMoreIcon />}
        >
          {mostrarTodos
            ? 'Mostrar menos'
            : `Ver mais ${cvesOrdenados.length - LIMITE_INICIAL} CVE(s)`}
        </Button>
      )}
    </Box>
  );
}
