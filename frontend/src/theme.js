import { createTheme, alpha } from '@mui/material/styles';

const NEON_CYAN = '#00d4ff';
const NEON_GREEN = '#00ff9d';
const BG_DEEP = '#060a10';
const BG_PAPER = '#0d1421';
const BG_CARD = '#111c2e';

const theme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: NEON_CYAN,
      dark: '#0099cc',
      light: '#4de6ff',
      contrastText: '#000',
    },
    secondary: {
      main: NEON_GREEN,
      dark: '#00cc7a',
      light: '#69ffbe',
      contrastText: '#000',
    },
    error:   { main: '#ff3b5c' },
    warning: { main: '#ffb830' },
    info:    { main: NEON_CYAN },
    success: { main: NEON_GREEN },
    background: {
      default: BG_DEEP,
      paper:   BG_PAPER,
    },
    text: {
      primary:   'rgba(255,255,255,0.92)',
      secondary: 'rgba(255,255,255,0.50)',
      disabled:  'rgba(255,255,255,0.28)',
    },
    divider: 'rgba(0,212,255,0.08)',
  },

  typography: {
    fontFamily: '"Inter", "Roboto", sans-serif',
    h1: { fontWeight: 800 },
    h2: { fontWeight: 800 },
    h3: { fontWeight: 700 },
    h4: { fontWeight: 700, letterSpacing: '-0.02em' },
    h5: { fontWeight: 700 },
    h6: { fontWeight: 600, letterSpacing: '0.01em' },
    body1: { fontSize: '0.95rem', lineHeight: 1.65 },
    body2: { fontSize: '0.85rem', lineHeight: 1.6 },
    caption: { fontSize: '0.75rem', letterSpacing: '0.06em', textTransform: 'uppercase' },
    overline: { fontWeight: 600 },
    button: { fontWeight: 600, textTransform: 'none', letterSpacing: '0.03em' },
    code: { fontFamily: '"JetBrains Mono", monospace', fontWeight: 600 },
  },

  shape: { borderRadius: 14 },

  shadows: [
    'none',
    `0 1px 4px 0 ${alpha('#000', 0.4)}`,
    `0 4px 16px 0 ${alpha('#000', 0.5)}`,
    `0 8px 24px 0 ${alpha('#000', 0.5)}`,
    `0 12px 40px 0 ${alpha('#000', 0.6)}`,
    `0 16px 48px 0 ${alpha('#000', 0.6)}`,
    ...Array(19).fill('none'),
  ],

  components: {
    MuiCssBaseline: {
      styleOverrides: {
        '*': { boxSizing: 'border-box', scrollbarWidth: 'thin', scrollbarColor: `${alpha(NEON_CYAN, 0.3)} transparent` },
        '*::-webkit-scrollbar': { width: 6, height: 6 },
        '*::-webkit-scrollbar-track': { background: 'transparent' },
        '*::-webkit-scrollbar-thumb': { background: alpha(NEON_CYAN, 0.3), borderRadius: 8 },
        body: { background: BG_DEEP },
      },
    },

    MuiAppBar: {
      styleOverrides: {
        root: {
          backgroundColor: alpha(BG_DEEP, 0.8),
          backdropFilter: 'blur(20px) saturate(1.5)',
          WebkitBackdropFilter: 'blur(20px) saturate(1.5)',
          backgroundImage: 'none',
          boxShadow: 'none',
          borderBottom: `1px solid ${alpha(NEON_CYAN, 0.1)}`,
        },
      },
    },

    MuiToolbar: {
      styleOverrides: {
        root: { minHeight: 64, '@media (min-width:600px)': { minHeight: 64 } },
      },
    },

    MuiCard: {
      styleOverrides: {
        root: {
          backgroundColor: BG_CARD,
          backgroundImage: 'none',
          border: `1px solid ${alpha(NEON_CYAN, 0.07)}`,
          boxShadow: `0 4px 24px 0 ${alpha('#000', 0.5)}`,
          transition: 'border-color 0.25s, box-shadow 0.25s',
          '&:hover': {
            borderColor: alpha(NEON_CYAN, 0.2),
            boxShadow: `0 8px 40px 0 ${alpha(NEON_CYAN, 0.08)}`,
          },
        },
      },
    },

    MuiPaper: {
      styleOverrides: {
        root: { backgroundImage: 'none' },
      },
    },

    MuiButton: {
      styleOverrides: {
        root: { borderRadius: 10, fontWeight: 600, padding: '10px 22px' },
        containedPrimary: {
          background: `linear-gradient(135deg, ${NEON_CYAN} 0%, ${alpha(NEON_CYAN, 0.7)} 100%)`,
          color: '#000',
          boxShadow: `0 4px 20px ${alpha(NEON_CYAN, 0.35)}`,
          '&:hover': { boxShadow: `0 6px 28px ${alpha(NEON_CYAN, 0.5)}` },
        },
        containedSecondary: {
          background: `linear-gradient(135deg, ${NEON_GREEN} 0%, ${alpha(NEON_GREEN, 0.7)} 100%)`,
          color: '#000',
          boxShadow: `0 4px 20px ${alpha(NEON_GREEN, 0.35)}`,
          '&:hover': { boxShadow: `0 6px 28px ${alpha(NEON_GREEN, 0.5)}` },
        },
        outlinedPrimary: {
          borderColor: alpha(NEON_CYAN, 0.5),
          '&:hover': { borderColor: NEON_CYAN, backgroundColor: alpha(NEON_CYAN, 0.06) },
        },
      },
    },

    MuiTextField: {
      styleOverrides: {
        root: {
          '& .MuiOutlinedInput-root': {
            backgroundColor: alpha('#fff', 0.03),
            borderRadius: 10,
            '& fieldset': { borderColor: alpha(NEON_CYAN, 0.15) },
            '&:hover fieldset': { borderColor: alpha(NEON_CYAN, 0.35) },
            '&.Mui-focused fieldset': { borderColor: NEON_CYAN, borderWidth: 1.5 },
          },
        },
      },
    },

    MuiChip: {
      styleOverrides: {
        root: { fontWeight: 700, letterSpacing: '0.06em', fontSize: '0.7rem' },
      },
    },

    MuiTableCell: {
      styleOverrides: {
        head: { fontWeight: 600, color: 'rgba(255,255,255,0.5)', fontSize: '0.72rem', letterSpacing: '0.08em', textTransform: 'uppercase', borderBottom: `1px solid ${alpha(NEON_CYAN, 0.1)}` },
        body: { borderBottom: `1px solid rgba(255,255,255,0.04)`, fontSize: '0.88rem' },
      },
    },

    MuiTableRow: {
      styleOverrides: {
        root: { '&:hover': { backgroundColor: alpha(NEON_CYAN, 0.03) } },
      },
    },

    MuiAccordion: {
      styleOverrides: {
        root: {
          backgroundColor: alpha('#fff', 0.02),
          backgroundImage: 'none',
          border: `1px solid ${alpha(NEON_CYAN, 0.07)}`,
          borderRadius: '12px !important',
          '&:before': { display: 'none' },
          '&.Mui-expanded': { borderColor: alpha(NEON_CYAN, 0.2), margin: '0 0 8px 0' },
          marginBottom: 8,
        },
      },
    },

    MuiAccordionSummary: {
      styleOverrides: {
        root: { borderRadius: 12 },
        expandIconWrapper: { color: alpha(NEON_CYAN, 0.7) },
      },
    },

    MuiTabs: {
      styleOverrides: {
        indicator: { background: `linear-gradient(90deg, ${NEON_CYAN}, ${NEON_GREEN})`, height: 2, borderRadius: 2 },
        root: { borderBottom: `1px solid ${alpha('#fff', 0.06)}` },
      },
    },

    MuiTab: {
      styleOverrides: {
        root: {
          fontWeight: 600,
          textTransform: 'none',
          fontSize: '0.88rem',
          letterSpacing: '0.02em',
          minHeight: 52,
          '&.Mui-selected': { color: NEON_CYAN },
        },
      },
    },

    MuiLinearProgress: {
      styleOverrides: {
        root: { borderRadius: 8, height: 8, backgroundColor: alpha('#fff', 0.07) },
      },
    },

    MuiSkeleton: {
      styleOverrides: {
        root: { backgroundColor: alpha(NEON_CYAN, 0.05) },
      },
    },

    MuiDataGrid: {
      styleOverrides: {
        root: {
          border: 'none',
          '& .MuiDataGrid-columnHeaders': { backgroundColor: alpha(NEON_CYAN, 0.04), borderBottom: `1px solid ${alpha(NEON_CYAN, 0.1)}` },
          '& .MuiDataGrid-row:hover': { backgroundColor: alpha(NEON_CYAN, 0.04) },
          '& .MuiDataGrid-footerContainer': { borderTop: `1px solid ${alpha(NEON_CYAN, 0.1)}` },
        },
      },
    },

    MuiDrawer: {
      styleOverrides: {
        paper: { backgroundColor: BG_PAPER, borderLeft: `1px solid ${alpha(NEON_CYAN, 0.1)}` },
      },
    },

    MuiAlert: {
      styleOverrides: {
        root: { borderRadius: 12 },
      },
    },
  },
});

export default theme;
