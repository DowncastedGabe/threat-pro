import React from 'react';
import { Box } from '@mui/material';

import Navbar from '../components/Navbar';

export default function AppLayout({ children }) {
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
      <Navbar />
      <Box component="main" sx={{ flexGrow: 1, pt: '64px' }}>
        {children}
      </Box>
    </Box>
  );
}
