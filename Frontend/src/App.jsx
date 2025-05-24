import axios from "axios";
import { Route, Routes, useNavigate, useLocation } from "react-router-dom";
import { useEffect, useState, useCallback } from "react";
import Home from "./auth/Home";
import VerifyEmailPage from "./auth/VerifyEmailPage";
import ForgotPasswordPage from "./auth/ForgotPasswordPage";
import ResetPasswordPage from "./auth/ResetPasswordPage";
import IndexPage from "./pages/index";
import PublicProfilePage from "./pages/PublicProfilePage";
import { Navbar } from "./components/navbar";
import LoginPage from "./auth/LoginPage";
import SignupPage from "./auth/SignupPage";
import ProtectedRoute from "./components/Layout/ProtectedRoute";
import PublicOnlyRoute from "./components/Layout/PublicOnlyRoute";

// Configure axios defaults
axios.defaults.baseURL = import.meta.env.VITE_BACKEND_URL;
axios.defaults.withCredentials = true;

function App() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();
  const location = useLocation();

  // Add axios response interceptor for handling 401 errors
  useEffect(() => {
    const interceptor = axios.interceptors.response.use(
      response => response,
      error => {
        if (error.response?.status === 401) {
          setUser(null);
          if (location.pathname !== "/login") {
            navigate("/login", { state: { from: location }, replace: true });
          }
        }
        return Promise.reject(error);
      }
    );

    return () => {
      axios.interceptors.response.eject(interceptor);
    };
  }, [navigate, location]);

  const checkAuth = useCallback(async () => {
    try {
      const { data } = await axios.get("/check-auth");
      if (data.authenticated) {
        setUser(data.user);
        // If on login/signup page but already authenticated, redirect to dashboard
        if (["/login", "/signup"].includes(location.pathname)) {
          navigate("/dashboard", { replace: true });
        }
      } else {
        setUser(null);
      }
    } catch (error) {
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, [navigate, location.pathname]);

  // Debounced auth check on initial load and route changes
  useEffect(() => {
    const timer = setTimeout(() => {
      checkAuth();
    }, 200);

    return () => clearTimeout(timer);
  }, [checkAuth]);

  // Show loading state only on initial load
  if (loading && location.pathname !== "/" && !user) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500 mx-auto"></div>
          <p className="mt-4 text-gray-600">Checking authentication...</p>
        </div>
      </div>
    );
  }

  // Determine if navbar should be hidden (for public profile pages)
  const isPublicProfileRoute = /^\/[^/]+$/.test(location.pathname);
  const hideNavbar = isPublicProfileRoute && !["/", "/login", "/signup"].some(
    route => location.pathname.startsWith(route)
  );

  return (
    <>
      {!hideNavbar && <Navbar user={user} setUser={setUser} />}
      <Routes>
        {/* Public routes */}
        <Route path="/" element={<Home user={user} />} />
        <Route path="/verify-email/:token" element={<VerifyEmailPage />} />
        <Route path="/forgot-password" element={<ForgotPasswordPage />} />
        <Route path="/reset-password/:token" element={<ResetPasswordPage />} />
        <Route path="/:username" element={<PublicProfilePage />} />
        
        {/* Auth-only routes */}
        <Route
          path="/dashboard"
          element={
            <ProtectedRoute user={user}>
              <IndexPage />
            </ProtectedRoute>
          }
        />
        
        {/* Public-only routes (no access when logged in) */}
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
      </Routes>
    </>
  );
}

export default App;