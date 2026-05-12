import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  alpha, AppBar, Box, Button, Container, Divider, Drawer,
  IconButton, InputBase, List, ListItemButton, ListItemIcon,
  ListItemText, Menu, MenuItem, Toolbar, Tooltip, Typography,
  useMediaQuery, useScrollTrigger, useTheme,
} from '@mui/material';
import { Link as RouterLink, useLocation, useNavigate } from 'react-router-dom';

import BugReportIcon       from '@mui/icons-material/BugReport';
import CircleIcon          from '@mui/icons-material/Circle';
import CloseIcon           from '@mui/icons-material/Close';
import DashboardIcon       from '@mui/icons-material/Dashboard';
import ExpandMoreIcon      from '@mui/icons-material/ExpandMore';
import LogoutIcon          from '@mui/icons-material/Logout';
import ManageSearchIcon    from '@mui/icons-material/ManageSearch';
import MenuIcon            from '@mui/icons-material/Menu';
import PublicIcon          from '@mui/icons-material/Public';
import RouterIcon          from '@mui/icons-material/Router';
import ScheduleIcon        from '@mui/icons-material/Schedule';
import SearchIcon          from '@mui/icons-material/Search';
import SecurityIcon        from '@mui/icons-material/Security';
import ShieldIcon          from '@mui/icons-material/Shield';
import StorageIcon         from '@mui/icons-material/Storage';
import TravelExploreIcon   from '@mui/icons-material/TravelExplore';
import VpnLockIcon         from '@mui/icons-material/VpnLock';

import { useAuth } from '../hooks/useAuth';
import api from '../api';

const NAV_GROUPS = [
  {
    label: 'Investigação',
    accent: '#00d4ff',
    items: [
      { to: '/',        icon: <SecurityIcon      sx={{ fontSize: 18 }} />, label: 'Análise de IP' },
      { to: '/site',    icon: <TravelExploreIcon sx={{ fontSize: 18 }} />, label: 'Análise de Site' },
      { to: '/osint',   icon: <ManageSearchIcon  sx={{ fontSize: 18 }} />, label: 'OSINT Dorker' },
      { to: '/sandbox', icon: <BugReportIcon     sx={{ fontSize: 18 }} />, label: 'SandBox', accent: '#ff1744' },
    ],
  },
  {
    label: 'Monitoramento',
    accent: '#00d4ff',
    items: [
      { to: '/dashboard', icon: <DashboardIcon sx={{ fontSize: 18 }} />, label: 'Dashboard' },
      { to: '/mapa',      icon: <PublicIcon     sx={{ fontSize: 18 }} />, label: 'Mapa de Calor' },
      { to: '/monitorar', icon: <ScheduleIcon   sx={{ fontSize: 18 }} />, label: 'Agendamentos' },
    ],
  },
  {
    label: 'Sistema',
    accent: '#00d4ff',
    items: [
      { to: '/roteador', icon: <RouterIcon  sx={{ fontSize: 18 }} />, label: 'Roteador' },
      { to: '/discos',   icon: <StorageIcon sx={{ fontSize: 18 }} />, label: 'Discos' },
    ],
  },
];

const SEARCH_PLACEHOLDER = 'Buscar IP, domínio ou URL…';

function useStatusIndicators() {
  const [tor, setTor]     = useState(null);
  const [db, setDb]       = useState(null);

  const poll = useCallback(async () => {
    try {
      const [torRes, healthRes] = await Promise.all([
        api.get('/osint/tor-status/').catch(() => null),
        api.get('/health').catch(() => null),
      ]);
      setTor(torRes?.data?.ativo ?? false);
      setDb(healthRes?.data?.status === 'ok');
    } catch {
      setTor(false);
      setDb(false);
    }
  }, []);

  useEffect(() => {
    poll();
    const id = setInterval(poll, 30_000);
    return () => clearInterval(id);
  }, [poll]);

  return { tor, db };
}

function StatusDot({ active, label, icon: Icon }) {
  const color   = active === null ? '#78909c' : active ? '#00ff9d' : '#ff1744';
  const tooltip = active === null ? `${label}: verificando…` : active ? `${label}: online` : `${label}: offline`;
  return (
    <Tooltip title={tooltip} arrow>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, cursor: 'default', px: 0.5 }}>
        <Icon sx={{ fontSize: 16, color: alpha(color, 0.7) }} />
        <CircleIcon sx={{ fontSize: 8, color, filter: active ? `drop-shadow(0 0 4px ${color})` : 'none', transition: 'all 0.4s' }} />
      </Box>
    </Tooltip>
  );
}

function GlobalSearch({ onSearch }) {
  const [value, setValue] = useState('');
  const inputRef          = useRef();

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && value.trim()) {
      onSearch(value.trim());
      setValue('');
    }
    if (e.key === 'Escape') {
      setValue('');
      inputRef.current?.blur();
    }
  };

  return (
    <Box
      sx={{
        display: 'flex', alignItems: 'center', gap: 1,
        bgcolor: 'rgba(0,212,255,0.04)',
        border: '1px solid rgba(0,212,255,0.15)',
        borderRadius: '10px',
        px: 1.5, py: 0.5,
        width: { sm: 220, md: 280 },
        transition: 'all 0.2s',
        '&:focus-within': {
          bgcolor: 'rgba(0,212,255,0.08)',
          borderColor: 'rgba(0,212,255,0.4)',
          boxShadow: '0 0 0 3px rgba(0,212,255,0.08)',
        },
      }}
    >
      <SearchIcon sx={{ fontSize: 16, color: 'rgba(0,212,255,0.5)', flexShrink: 0 }} />
      <InputBase
        inputRef={inputRef}
        value={value}
        onChange={(e) => setValue(e.target.value)}
        onKeyDown={handleKeyDown}
        placeholder={SEARCH_PLACEHOLDER}
        inputProps={{ 'aria-label': 'busca global' }}
        sx={{
          flex: 1,
          fontSize: '0.8rem',
          color: 'text.primary',
          '& ::placeholder': { color: 'rgba(255,255,255,0.3)', fontSize: '0.78rem' },
        }}
      />
      {value && (
        <IconButton size="small" onClick={() => setValue('')} sx={{ p: 0.2, color: 'text.disabled' }}>
          <CloseIcon sx={{ fontSize: 14 }} />
        </IconButton>
      )}
    </Box>
  );
}

function NavDropdown({ group, location }) {
  const [anchor, setAnchor] = useState(null);
  const open = Boolean(anchor);

  const isGroupActive = group.items.some((i) => location.pathname === i.to);
  const c = isGroupActive ? '#00d4ff' : 'rgba(255,255,255,0.6)';

  return (
    <>
      <Button
        size="small"
        onClick={(e) => setAnchor(e.currentTarget)}
        endIcon={<ExpandMoreIcon sx={{ fontSize: 14, transition: 'transform 0.2s', transform: open ? 'rotate(180deg)' : 'none' }} />}
        sx={{
          color: c,
          bgcolor: isGroupActive ? 'rgba(0,212,255,0.08)' : 'transparent',
          border: `1px solid ${isGroupActive ? 'rgba(0,212,255,0.22)' : 'transparent'}`,
          borderRadius: '10px',
          px: 1.6, py: 0.8,
          fontSize: '0.83rem',
          fontWeight: isGroupActive ? 600 : 400,
          transition: 'all 0.2s',
          '&:hover': { color: '#00d4ff', bgcolor: 'rgba(0,212,255,0.06)', borderColor: 'rgba(0,212,255,0.18)' },
        }}
      >
        {group.label}
      </Button>

      <Menu
        anchorEl={anchor}
        open={open}
        onClose={() => setAnchor(null)}
        transformOrigin={{ horizontal: 'left', vertical: 'top' }}
        anchorOrigin={{ horizontal: 'left', vertical: 'bottom' }}
        PaperProps={{
          sx: {
            mt: 0.5,
            bgcolor: 'rgba(10,14,26,0.92)',
            backdropFilter: 'blur(16px)',
            border: '1px solid rgba(0,212,255,0.14)',
            borderRadius: 2,
            minWidth: 200,
            boxShadow: '0 16px 40px rgba(0,0,0,0.5)',
          },
        }}
      >
        {group.items.map(({ to, icon, label, accent }) => {
          const active = location.pathname === to;
          const ic     = accent ?? '#00d4ff';
          return (
            <MenuItem
              key={to}
              component={RouterLink}
              to={to}
              onClick={() => setAnchor(null)}
              sx={{
                gap: 1.5, py: 1, px: 2,
                color: active ? ic : 'text.secondary',
                bgcolor: active ? alpha(ic, 0.07) : 'transparent',
                borderLeft: `2px solid ${active ? ic : 'transparent'}`,
                transition: 'all 0.15s',
                '&:hover': { color: ic, bgcolor: alpha(ic, 0.06) },
              }}
            >
              {React.cloneElement(icon, { sx: { fontSize: 18, color: active ? ic : 'inherit' } })}
              <Typography variant="body2" sx={{ fontWeight: active ? 600 : 400 }}>{label}</Typography>
            </MenuItem>
          );
        })}
      </Menu>
    </>
  );
}

function MobileDrawer({ open, onClose, location, logout, user }) {
  return (
    <Drawer
      anchor="left"
      open={open}
      onClose={onClose}
      PaperProps={{
        sx: {
          width: 280,
          bgcolor: 'rgba(8,12,22,0.97)',
          backdropFilter: 'blur(20px)',
          borderRight: '1px solid rgba(0,212,255,0.12)',
        },
      }}
    >
      <Box sx={{ p: 2, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Box sx={{
            width: 32, height: 32, borderRadius: '8px', display: 'flex', alignItems: 'center', justifyContent: 'center',
            background: 'linear-gradient(135deg, rgba(0,212,255,0.2), rgba(0,255,157,0.1))',
            border: '1px solid rgba(0,212,255,0.3)',
          }}>
            <ShieldIcon sx={{ color: 'primary.main', fontSize: 18 }} />
          </Box>
          <Box>
            <Typography variant="body2" sx={{ fontWeight: 800, lineHeight: 1.1 }}>ThreatIntel</Typography>
            <Typography variant="caption" sx={{ color: 'primary.main', fontSize: '0.6rem', letterSpacing: '0.1em' }}>PRO</Typography>
          </Box>
        </Box>
        <IconButton size="small" onClick={onClose} sx={{ color: 'text.secondary' }}>
          <CloseIcon fontSize="small" />
        </IconButton>
      </Box>

      <Divider sx={{ borderColor: 'rgba(0,212,255,0.08)' }} />

      <Box sx={{ overflowY: 'auto', flex: 1, py: 1 }}>
        {NAV_GROUPS.map((group) => (
          <Box key={group.label}>
            <Typography variant="caption" sx={{ px: 2, py: 1, display: 'block', color: 'rgba(0,212,255,0.5)', fontWeight: 700, letterSpacing: '0.08em', fontSize: '0.65rem' }}>
              {group.label.toUpperCase()}
            </Typography>
            <List dense disablePadding>
              {group.items.map(({ to, icon, label, accent }) => {
                const active = location.pathname === to;
                const ic = accent ?? '#00d4ff';
                return (
                  <ListItemButton
                    key={to}
                    component={RouterLink}
                    to={to}
                    onClick={onClose}
                    sx={{
                      px: 2, py: 0.8, mx: 1, borderRadius: 1.5,
                      color: active ? ic : 'text.secondary',
                      bgcolor: active ? alpha(ic, 0.1) : 'transparent',
                      borderLeft: `2px solid ${active ? ic : 'transparent'}`,
                      mb: 0.25,
                      '&:hover': { color: ic, bgcolor: alpha(ic, 0.07) },
                    }}
                  >
                    <ListItemIcon sx={{ minWidth: 32, color: 'inherit' }}>
                      {React.cloneElement(icon, { sx: { fontSize: 18, color: 'inherit' } })}
                    </ListItemIcon>
                    <ListItemText primary={label} primaryTypographyProps={{ variant: 'body2', fontWeight: active ? 600 : 400 }} />
                  </ListItemButton>
                );
              })}
            </List>
            <Divider sx={{ borderColor: 'rgba(255,255,255,0.04)', my: 0.5 }} />
          </Box>
        ))}
      </Box>

      <Divider sx={{ borderColor: 'rgba(0,212,255,0.08)' }} />
      <Box sx={{ p: 1.5 }}>
        <ListItemButton
          onClick={() => { logout(); onClose(); }}
          sx={{ borderRadius: 1.5, color: 'text.secondary', '&:hover': { color: '#ff1744', bgcolor: 'rgba(255,23,68,0.06)' } }}
        >
          <ListItemIcon sx={{ minWidth: 32, color: 'inherit' }}>
            <LogoutIcon sx={{ fontSize: 18 }} />
          </ListItemIcon>
          <ListItemText primary={user?.name ? `Sair (${user.name})` : 'Sair'} primaryTypographyProps={{ variant: 'body2' }} />
        </ListItemButton>
      </Box>
    </Drawer>
  );
}

export default function Navbar() {
  const location  = useLocation();
  const navigate  = useNavigate();
  const theme     = useTheme();
  const isMobile  = useMediaQuery(theme.breakpoints.down('md'));
  const scrolled  = useScrollTrigger({ disableHysteresis: true, threshold: 10 });
  const { user, isAuthenticated, logout } = useAuth();
  const { tor, db } = useStatusIndicators();
  const [drawerOpen, setDrawerOpen] = useState(false);

  const handleSearch = useCallback((query) => {
    const isIP  = /^(\d{1,3}\.){3}\d{1,3}$/.test(query);
    const isURL = query.startsWith('http://') || query.startsWith('https://') || query.includes('.');
    if (isIP)  return navigate(`/?ip=${encodeURIComponent(query)}`);
    if (isURL) return navigate(`/site?url=${encodeURIComponent(query)}`);
    navigate(`/?ip=${encodeURIComponent(query)}`);
  }, [navigate]);

  return (
    <>
      <AppBar
        position="fixed"
        elevation={0}
        sx={{
          backdropFilter: 'blur(20px)',
          WebkitBackdropFilter: 'blur(20px)',
          bgcolor: scrolled ? 'rgba(8,12,22,0.88)' : 'rgba(8,12,22,0.6)',
          borderBottom: `1px solid ${scrolled ? 'rgba(0,212,255,0.18)' : 'rgba(0,212,255,0.07)'}`,
          transition: 'background-color 0.3s, border-color 0.3s',
        }}
      >
        <Container maxWidth="xl" disableGutters sx={{ px: { xs: 1.5, sm: 2.5 } }}>
          <Toolbar sx={{ gap: 1, minHeight: { xs: 56, sm: 64 } }}>

            {isMobile && isAuthenticated && (
              <IconButton
                size="small"
                onClick={() => setDrawerOpen(true)}
                sx={{ color: 'text.secondary', mr: 0.5 }}
                aria-label="abrir menu"
              >
                <MenuIcon />
              </IconButton>
            )}

            <Box
              component={RouterLink}
              to="/"
              sx={{ display: 'flex', alignItems: 'center', gap: 1, textDecoration: 'none', flexShrink: 0 }}
            >
              <Box sx={{
                width: 34, height: 34, borderRadius: '9px', display: 'flex', alignItems: 'center', justifyContent: 'center',
                background: 'linear-gradient(135deg, rgba(0,212,255,0.22), rgba(0,255,157,0.1))',
                border: '1px solid rgba(0,212,255,0.3)',
              }}>
                <ShieldIcon sx={{ color: 'primary.main', fontSize: 19 }} />
              </Box>
              <Box sx={{ display: { xs: 'none', sm: 'block' } }}>
                <Typography variant="body2" sx={{ fontWeight: 800, color: 'white', lineHeight: 1.1, letterSpacing: '-0.02em' }}>
                  ThreatIntel
                </Typography>
                <Typography variant="caption" sx={{ color: 'primary.main', lineHeight: 1, letterSpacing: '0.12em', display: 'block', fontSize: '0.6rem' }}>
                  PRO
                </Typography>
              </Box>
            </Box>

            {!isMobile && isAuthenticated && (
              <>
                <Box sx={{ width: 1, maxWidth: 32 }} />
                <Box sx={{ display: 'flex', gap: 0.5 }}>
                  {NAV_GROUPS.map((group) => (
                    <NavDropdown key={group.label} group={group} location={location} />
                  ))}
                </Box>
              </>
            )}

            <Box sx={{ flex: 1 }} />

            {isAuthenticated && (
              <GlobalSearch onSearch={handleSearch} />
            )}

            {isAuthenticated && !isMobile && (
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mx: 0.5 }}>
                <StatusDot active={tor} label="Tor Proxy" icon={VpnLockIcon} />
                <StatusDot active={db}  label="PostgreSQL" icon={StorageIcon} />
              </Box>
            )}

            {isAuthenticated && !isMobile && (
              <Tooltip title={user?.name ? `Sair (${user.name})` : 'Sair'} arrow>
                <Button
                  size="small"
                  onClick={logout}
                  startIcon={<LogoutIcon sx={{ fontSize: 16 }} />}
                  sx={{
                    color: 'text.secondary', borderRadius: '10px', px: 1.6, py: 0.8,
                    fontSize: '0.8rem', ml: 0.5,
                    '&:hover': { color: '#ff1744', bgcolor: 'rgba(255,23,68,0.06)' },
                  }}
                >
                  {user?.name ?? 'Sair'}
                </Button>
              </Tooltip>
            )}

          </Toolbar>
        </Container>
      </AppBar>

      {isAuthenticated && (
        <MobileDrawer
          open={drawerOpen}
          onClose={() => setDrawerOpen(false)}
          location={location}
          logout={logout}
          user={user}
        />
      )}
    </>
  );
}
