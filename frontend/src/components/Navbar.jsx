import React from 'react';
import { AppBar, Toolbar, Typography, Button, Box, Container, useScrollTrigger, alpha } from '@mui/material';
import { Link as RouterLink, useLocation } from 'react-router-dom';
import SecurityIcon from '@mui/icons-material/Security';
import TravelExploreIcon from '@mui/icons-material/TravelExplore';
import ShieldIcon from '@mui/icons-material/Shield';
import DashboardIcon from '@mui/icons-material/Dashboard';
import PublicIcon from '@mui/icons-material/Public';
import ScheduleIcon from '@mui/icons-material/Schedule';
import ManageSearchIcon from '@mui/icons-material/ManageSearch';
import RouterIcon from '@mui/icons-material/Router';
import StorageIcon from '@mui/icons-material/Storage';
import LogoutIcon from '@mui/icons-material/Logout';
import { useAuth } from '../hooks/useAuth';

const LINKS = [
  { to: '/dashboard',  icon: <DashboardIcon      sx={{ fontSize: 18 }} />, label: 'Dashboard' },
  { to: '/',           icon: <SecurityIcon        sx={{ fontSize: 18 }} />, label: 'Análise de IP' },
  { to: '/site',       icon: <TravelExploreIcon   sx={{ fontSize: 18 }} />, label: 'Análise de Site' },
  { to: '/mapa',       icon: <PublicIcon          sx={{ fontSize: 18 }} />, label: 'Mapa' },
  { to: '/monitorar',  icon: <ScheduleIcon        sx={{ fontSize: 18 }} />, label: 'Monitorar' },
  { to: '/osint',      icon: <ManageSearchIcon    sx={{ fontSize: 18 }} />, label: 'OSINT' },
  { to: '/roteador',   icon: <RouterIcon          sx={{ fontSize: 18 }} />, label: 'Roteador' },
  { to: '/discos',     icon: <StorageIcon         sx={{ fontSize: 18 }} />, label: 'Discos' },
];

export default function Navbar() {
  const location = useLocation();
  const scrolled = useScrollTrigger({ disableHysteresis: true, threshold: 10 });
  const { user, isAuthenticated, logout } = useAuth();

  return (
    <AppBar
      position="fixed"
      elevation={0}
      sx={{
        borderBottom: scrolled
          ? '1px solid rgba(0,212,255,0.18)'
          : '1px solid rgba(0,212,255,0.07)',
        transition: 'border-color 0.3s',
      }}
    >
      <Container maxWidth="xl" disableGutters sx={{ px: { xs: 2, sm: 3 } }}>
        <Toolbar sx={{ gap: 1 }}>
          {/* BRAND */}
          <Box
            component={RouterLink}
            to="/"
            sx={{ display: 'flex', alignItems: 'center', gap: 1, textDecoration: 'none', mr: 4 }}
          >
            <Box
              sx={{
                width: 36, height: 36, borderRadius: '10px', display: 'flex', alignItems: 'center', justifyContent: 'center',
                background: 'linear-gradient(135deg, rgba(0,212,255,0.2), rgba(0,255,157,0.1))',
                border: '1px solid rgba(0,212,255,0.3)',
              }}
            >
              <ShieldIcon sx={{ color: 'primary.main', fontSize: 20 }} />
            </Box>
            <Box>
              <Typography
                variant="body1"
                sx={{ fontWeight: 800, color: 'white', lineHeight: 1.1, letterSpacing: '-0.02em' }}
              >
                ThreatIntel
              </Typography>
              <Typography variant="caption" sx={{ color: 'primary.main', lineHeight: 1, letterSpacing: '0.1em', display: 'block', fontSize: '0.65rem' }}>
                PRO
              </Typography>
            </Box>
          </Box>

          <Box sx={{ flexGrow: 1 }} />

          {/* NAV LINKS */}
          <Box sx={{ display: 'flex', gap: 0.5 }}>
            {isAuthenticated && LINKS.map(({ to, icon, label }) => {
              const active = location.pathname === to;
              return (
                <Button
                  key={to}
                  component={RouterLink}
                  to={to}
                  startIcon={icon}
                  size="small"
                  sx={{
                    color: active ? 'primary.main' : 'text.secondary',
                    backgroundColor: active ? alpha('#00d4ff', 0.08) : 'transparent',
                    border: `1px solid ${active ? alpha('#00d4ff', 0.25) : 'transparent'}`,
                    borderRadius: '10px',
                    px: 1.8,
                    py: 0.8,
                    fontSize: '0.83rem',
                    transition: 'all 0.2s',
                    '&:hover': {
                      color: 'primary.main',
                      backgroundColor: alpha('#00d4ff', 0.06),
                      borderColor: alpha('#00d4ff', 0.2),
                    },
                  }}
                >
                  {label}
                </Button>
              );
            })}
            {isAuthenticated && (
              <Button
                size="small"
                startIcon={<LogoutIcon sx={{ fontSize: 18 }} />}
                onClick={logout}
                sx={{ color: 'text.secondary', borderRadius: '10px', px: 1.8, py: 0.8 }}
              >
                {user?.name ? `Sair (${user.name})` : 'Sair'}
              </Button>
            )}
          </Box>
        </Toolbar>
      </Container>
    </AppBar>
  );
}
