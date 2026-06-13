import { Navigate, Route, Routes } from 'react-router-dom';
import Layout from './components/layout/Layout';
import ProtectedRoute from './components/guards/ProtectedRoute';
import AdminRoute from './components/guards/AdminRoute';
import HomePage from './pages/HomePage';
import LoginPage from './pages/auth/LoginPage';
import RegisterPage from './pages/auth/RegisterPage';
import PublicVerifyPage from './pages/verify/PublicVerifyPage';
import DashboardPage from './pages/dashboard/DashboardPage';
import ContentListPage from './pages/content/ContentListPage';
import ContentCreatePage from './pages/content/ContentCreatePage';
import ContentDetailPage from './pages/content/ContentDetailPage';
import AdminDashboardPage from './pages/admin/AdminDashboardPage';
import CaseListPage from './pages/cases/CaseListPage';
import CaseDetailPage from './pages/cases/CaseDetailPage';
import AuditLogPage from './pages/audit/AuditLogPage';
import ThreeDashboardPage from './pages/dashboard/ThreeDashboardPage';
import ATSPage from './pages/ats/ATSPage';
import PlagiarismPage from './pages/plagiarism/PlagiarismPage';
import ProfilePage from './pages/profile/ProfilePage';
import SettingsPage from './pages/settings/SettingsPage';

function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/" element={<HomePage />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/register" element={<RegisterPage />} />
        <Route path="/verify" element={<PublicVerifyPage />} />

        <Route element={<ProtectedRoute />}>
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/dashboard/3d" element={<ThreeDashboardPage />} />
          <Route path="/content" element={<ContentListPage />} />
          <Route path="/content/new" element={<ContentCreatePage />} />
          <Route path="/content/:id" element={<ContentDetailPage />} />
          <Route path="/cases" element={<CaseListPage />} />
          <Route path="/cases/:id" element={<CaseDetailPage />} />
          <Route path="/ats" element={<ATSPage />} />
          <Route path="/plagiarism" element={<PlagiarismPage />} />
          <Route path="/audit" element={<AuditLogPage />} />
          <Route path="/profile" element={<ProfilePage />} />
          <Route path="/settings" element={<SettingsPage />} />
        </Route>

        <Route element={<AdminRoute />}>
          <Route path="/admin" element={<AdminDashboardPage />} />
        </Route>

        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}

export default App;
