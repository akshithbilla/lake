// App.jsx
import { useState, useEffect } from 'react';
import { Routes, Route, useNavigate } from 'react-router-dom';
import axios from 'axios';
import Navbar from './components/Navbar';
import Home from './pages/Home';
import VerifyEmailPage from './pages/VerifyEmailPage';
import ForgotPasswordPage from './pages/ForgotPasswordPage';
import ResetPasswordPage from './pages/ResetPasswordPage';
import LoginPage from './pages/LoginPage';
import SignupPage from './pages/SignupPage';
import IndexPage from "./pages/index";
import PublicProfilePage from './pages/PublicProfilePage';
import PageNotFound from './pages/PageNotFound';
import ProtectedRoute from './components/Layout/ProtectedRoute';
import PublicOnlyRoute from './components/Layout/PublicOnlyRoute';

function App() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [hideNavbar, setHideNavbar] = useState(false);
  const navigate = useNavigate();

  // Check auth status on initial load
  useEffect(() => {
    const checkAuth = async () => {
      try {
        const token = localStorage.getItem('token');
        if (token) {
          const response = await axios.get('/check-auth', {
            headers: { Authorization: `Bearer ${token}` }
          });
          if (response.data.authenticated) {
            setUser(response.data.user);
            // Redirect to dashboard if authenticated and on home page
            if (window.location.pathname === '/') {
              navigate('/dashboard');
            }
          }
        }
      } catch (err) {
        console.error('Auth check failed:', err);
        localStorage.removeItem('token');
      } finally {
        setLoading(false);
      }
    };

    checkAuth();
  }, [navigate]);

  const checkAuth = async () => {
    try {
      const token = localStorage.getItem('token');
      if (token) {
        const response = await axios.get('/check-auth', {
          headers: { Authorization: `Bearer ${token}` }
        });
        if (response.data.authenticated) {
          setUser(response.data.user);
          return true;
        }
      }
      return false;
    } catch (err) {
      console.error('Auth check failed:', err);
      return false;
    }
  };

  if (loading) {
    return <div>Loading...</div>;
  }

  return (
    <>
      {!hideNavbar && <Navbar user={user} setUser={setUser} />}
      <Routes>
        {/* Public routes */}
        <Route path="/" element={<Home user={user} />} />
        <Route
          path="/verify-email/:token"
          element={<VerifyEmailPage refreshUser={checkAuth} />}
        />
        <Route path="/forgot-password" element={<ForgotPasswordPage />} />
        <Route
          path="/reset-password/:token"
          element={<ResetPasswordPage refreshUser={checkAuth} />}
        />
        <Route
          path="/login"
          element={
            <PublicOnlyRoute user={user}>
              <LoginPage setUser={setUser} />
            </PublicOnlyRoute>
          }
        />
        <Route
          path="/signup"
          element={
            <PublicOnlyRoute user={user}>
              <SignupPage />
            </PublicOnlyRoute>
          }
        />
        
        {/* Protected routes */}
        <Route
          path="/dashboard"
          element={
            <ProtectedRoute user={user}>
              <IndexPage user={user} />
            </ProtectedRoute>
          }
        />
        
        {/* Public profile route */}
        <Route path="/:username" element={<PublicProfilePage />} />
        
        {/* 404 route */}
        <Route path="*" element={<PageNotFound />} />
      </Routes>
    </>
  );
}

export default App;