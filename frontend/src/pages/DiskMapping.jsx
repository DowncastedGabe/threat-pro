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
  TextField,
  Typography,
  alpha,
} from '@mui/material';
import StorageIcon from '@mui/icons-material/Storage';
import FolderIcon from '@mui/icons-material/Folder';
import InsertDriveFileIcon from '@mui/icons-material/InsertDriveFile';
import RefreshIcon from '@mui/icons-material/Refresh';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import { scanDiskMapping } from '../services/diskMappingService';

const statusColor = {
  healthy: 'success',
  warning: 'warning',
  critical: 'error',
};

const statusLabel = {
  healthy: 'Saudavel',
  warning: 'Atencao',
  critical: 'Critico',
};

function formatBytes(bytes) {
  if (bytes === null || bytes === undefined) return '-';
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / 1024 ** index).toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}

function TreeNode({ node, level = 0 }) {
  const isDir = node.type === 'directory';

  return (
    <Box sx={{ ml: level ? 2 : 0, mt: 0.7 }}>
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          gap: 1,
          p: 1,
          borderRadius: 1,
          backgroundColor: alpha('#fff', isDir ? 0.025 : 0.012),
          border: `1px solid ${alpha('#00d4ff', isDir ? 0.08 : 0.04)}`,
        }}
      >
        {isDir ? (
          <FolderIcon sx={{ color: 'primary.main', fontSize: 18 }} />
        ) : (
          <InsertDriveFileIcon sx={{ color: 'text.secondary', fontSize: 18 }} />
        )}
        <Typography
          variant="body2"
          sx={{
            flex: 1,
            fontWeight: isDir ? 700 : 500,
            wordBreak: 'break-all',
          }}
        >
          {node.name}
        </Typography>
        {isDir && node.children_count !== null && node.children_count !== undefined && (
          <Chip size="small" label={`${node.children_count} itens`} variant="outlined" />
        )}
        {!isDir && <Typography variant="caption" color="text.secondary">{formatBytes(node.size_bytes)}</Typography>}
        {node.is_truncated && <Chip size="small" color="warning" label="Limitado" />}
      </Box>
      {node.children?.map((child) => (
        <TreeNode key={`${child.path}-${child.name}`} node={child} level={level + 1} />
      ))}
    </Box>
  );
}

export default function DiskMapping() {
  const [rootPath, setRootPath] = useState('');
  const [maxDepth, setMaxDepth] = useState(2);
  const [maxNodes, setMaxNodes] = useState(250);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const totals = useMemo(() => {
    const partitions = result?.partitions || [];
    const totalBytes = partitions.reduce((sum, item) => sum + item.total_bytes, 0);
    const usedBytes = partitions.reduce((sum, item) => sum + item.used_bytes, 0);
    const percent = totalBytes ? Math.round((usedBytes / totalBytes) * 1000) / 10 : 0;
    return { totalBytes, usedBytes, percent, count: partitions.length };
  }, [result]);

  const handleSubmit = async (event) => {
    event?.preventDefault();
    setLoading(true);
    setError('');

    try {
      const data = await scanDiskMapping({
        root_path: rootPath.trim() || null,
        max_depth: Number(maxDepth) || 2,
        max_nodes: Number(maxNodes) || 250,
      });
      setResult(data);
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Falha ao mapear disco.');
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
          <StorageIcon sx={{ color: 'primary.main', fontSize: 34 }} />
        </Box>
        <Typography variant="h4" gutterBottom sx={{ fontWeight: 800 }}>
          Mapeamento de Disco
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ maxWidth: 680, mx: 'auto' }}>
          Visualize volumes, consumo de armazenamento e uma arvore limitada de diretorios autorizados.
        </Typography>
      </Box>

      <Card sx={{ mb: 3 }}>
        <CardContent sx={{ p: 3 }}>
          <Box component="form" onSubmit={handleSubmit}>
            <Grid container spacing={2} alignItems="center">
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Diretorio para arvore"
                  placeholder="Opcional: deixe vazio para listar apenas volumes"
                  value={rootPath}
                  onChange={(event) => setRootPath(event.target.value)}
                  disabled={loading}
                  helperText="O backend aceita somente caminhos dentro da allowlist."
                />
              </Grid>
              <Grid item xs={6} md={2}>
                <TextField
                  fullWidth
                  type="number"
                  label="Profundidade"
                  value={maxDepth}
                  onChange={(event) => setMaxDepth(event.target.value)}
                  disabled={loading}
                  inputProps={{ min: 0, max: 5 }}
                />
              </Grid>
              <Grid item xs={6} md={2}>
                <TextField
                  fullWidth
                  type="number"
                  label="Max. itens"
                  value={maxNodes}
                  onChange={(event) => setMaxNodes(event.target.value)}
                  disabled={loading}
                  inputProps={{ min: 1, max: 1000 }}
                />
              </Grid>
              <Grid item xs={12} md={2}>
                <Button
                  fullWidth
                  variant="contained"
                  type="submit"
                  disabled={loading}
                  startIcon={loading ? <CircularProgress size={18} color="inherit" /> : <RefreshIcon />}
                  sx={{ height: 56 }}
                >
                  {loading ? 'Mapeando...' : 'Mapear'}
                </Button>
              </Grid>
            </Grid>
          </Box>
        </CardContent>
      </Card>

      {error && <Alert severity="error" sx={{ mb: 3 }}>{error}</Alert>}

      {result && (
        <Stack spacing={3}>
          <Grid container spacing={3}>
            <Grid item xs={12} md={4}>
              <Card sx={{ height: '100%' }}>
                <CardContent sx={{ p: 3 }}>
                  <Stack direction="row" spacing={1.5} alignItems="center" sx={{ mb: 2 }}>
                    <StorageIcon sx={{ color: 'primary.main' }} />
                    <Typography variant="h6">Uso consolidado</Typography>
                  </Stack>
                  <Typography variant="h3" sx={{ fontWeight: 900 }}>{totals.percent}%</Typography>
                  <LinearProgress
                    variant="determinate"
                    value={totals.percent}
                    color={totals.percent >= 90 ? 'error' : totals.percent >= 75 ? 'warning' : 'success'}
                    sx={{ my: 2 }}
                  />
                  <Typography variant="body2" color="text.secondary">
                    {formatBytes(totals.usedBytes)} usados de {formatBytes(totals.totalBytes)}
                  </Typography>
                  <Chip sx={{ mt: 2 }} label={`${totals.count} volume(s)`} color="primary" variant="outlined" />
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} md={8}>
              <Card sx={{ height: '100%' }}>
                <CardContent sx={{ p: 3 }}>
                  <Typography variant="h6" sx={{ mb: 2 }}>Allowlist ativa</Typography>
                  <Stack spacing={1}>
                    {result.allowed_roots.map((root) => (
                      <Alert key={root} severity="info" variant="outlined">
                        <Typography sx={{ fontFamily: '"JetBrains Mono", monospace', wordBreak: 'break-all' }}>
                          {root}
                        </Typography>
                      </Alert>
                    ))}
                  </Stack>
                </CardContent>
              </Card>
            </Grid>
          </Grid>

          <Grid container spacing={3}>
            {result.partitions.map((partition) => (
              <Grid item xs={12} md={6} key={`${partition.device}-${partition.mountpoint}`}>
                <Card sx={{ height: '100%' }}>
                  <CardContent sx={{ p: 3 }}>
                    <Stack direction="row" spacing={1.5} alignItems="center" sx={{ mb: 2 }}>
                      <StorageIcon sx={{ color: 'primary.main' }} />
                      <Box sx={{ flex: 1, minWidth: 0 }}>
                        <Typography variant="h6" sx={{ wordBreak: 'break-all' }}>{partition.mountpoint}</Typography>
                        <Typography variant="caption" color="text.secondary">{partition.device} | {partition.filesystem}</Typography>
                      </Box>
                      <Chip
                        color={statusColor[partition.status] || 'default'}
                        label={statusLabel[partition.status] || partition.status}
                      />
                    </Stack>
                    <LinearProgress
                      variant="determinate"
                      value={partition.percent_used}
                      color={statusColor[partition.status] || 'primary'}
                      sx={{ mb: 2 }}
                    />
                    <Grid container spacing={2}>
                      <Grid item xs={4}>
                        <Typography variant="caption" color="text.secondary">Usado</Typography>
                        <Typography sx={{ fontWeight: 800 }}>{formatBytes(partition.used_bytes)}</Typography>
                      </Grid>
                      <Grid item xs={4}>
                        <Typography variant="caption" color="text.secondary">Livre</Typography>
                        <Typography sx={{ fontWeight: 800 }}>{formatBytes(partition.free_bytes)}</Typography>
                      </Grid>
                      <Grid item xs={4}>
                        <Typography variant="caption" color="text.secondary">Total</Typography>
                        <Typography sx={{ fontWeight: 800 }}>{formatBytes(partition.total_bytes)}</Typography>
                      </Grid>
                    </Grid>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          {result.tree && (
            <Card>
              <CardContent sx={{ p: 3 }}>
                <Stack direction="row" spacing={1.5} alignItems="center" sx={{ mb: 2 }}>
                  <FolderIcon sx={{ color: 'primary.main' }} />
                  <Typography variant="h6">Arvore de diretorios</Typography>
                </Stack>
                <TreeNode node={result.tree} />
              </CardContent>
            </Card>
          )}

          {result.warnings?.length > 0 && (
            <Card>
              <CardContent sx={{ p: 3 }}>
                <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 2 }}>
                  <WarningAmberIcon sx={{ color: 'warning.main' }} />
                  <Typography variant="h6">Avisos</Typography>
                </Stack>
                <Stack spacing={1}>
                  {result.warnings.map((warning) => (
                    <Alert key={warning} severity="warning" variant="outlined">{warning}</Alert>
                  ))}
                </Stack>
              </CardContent>
            </Card>
          )}

          {!result.warnings?.length && (
            <Alert severity="success" icon={<CheckCircleIcon />}>
              Mapeamento concluido dentro dos limites configurados.
            </Alert>
          )}
        </Stack>
      )}
    </Container>
  );
}
