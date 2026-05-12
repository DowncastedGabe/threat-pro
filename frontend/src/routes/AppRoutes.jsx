import React from 'react';
import { Route, Routes } from 'react-router-dom';

import Dashboard from '../pages/Dashboard';
import DiskMapping from '../pages/DiskMapping';
import HeatMap from '../pages/HeatMap';
import IpAnalysis from '../pages/IpAnalysis';
import Monitoring from '../pages/Monitoring';
import OsintDorker from '../pages/OsintDorker';
import RouterProtection from '../pages/RouterProtection';
import SiteAnalysis from '../pages/SiteAnalysis';
import Login from '../pages/Login';
import Register from '../pages/Register';
import ProtectedRoute from './ProtectedRoute';

export default function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />
      <Route path="/" element={<ProtectedRoute><IpAnalysis /></ProtectedRoute>} />
      <Route path="/site" element={<ProtectedRoute><SiteAnalysis /></ProtectedRoute>} />
      <Route path="/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
      <Route path="/mapa" element={<ProtectedRoute><HeatMap /></ProtectedRoute>} />
      <Route path="/monitorar" element={<ProtectedRoute><Monitoring /></ProtectedRoute>} />
      <Route path="/osint" element={<ProtectedRoute><OsintDorker /></ProtectedRoute>} />
      <Route path="/roteador" element={<ProtectedRoute><RouterProtection /></ProtectedRoute>} />
      <Route path="/discos" element={<ProtectedRoute><DiskMapping /></ProtectedRoute>} />
    </Routes>
  );
}
