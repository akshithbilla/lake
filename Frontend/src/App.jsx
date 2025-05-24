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
axios.defaults.withCredentials = true;
axios.defaults.baseURL = import.meta.env.VITE_BACKEND_URL;

function App() {
  const [user, setUser] = useState(null);
  const [initialAuthCheckDone, setInitialAuthCheckDone] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();
  const authCheckTimeout = useRef(null);

  // Add axios response interceptor
  useEffect(() => {
    const interceptor = axios.interceptors.response.use(
      response => response,
      error => {
        if (error.response?.status === 401) {
          setUser(null);
          // Only redirect if not already on login page
          if (!location.pathname.startsWith("/login")) {
            navigate("/login", { 
              state: { from: location },
              replace: true  // Prevent history buildup
            });
          }
        }
        return Promise.reject(error);
      }
    );

    return () => axios.interceptors.response.eject(interceptor);
  }, [navigate, location]);

  const checkAuth = useCallback(async () => {
    try {
      const { data } = await axios.get("/check-auth");
      
      if (data.authenticated) {
        setUser(data.user);
        // Redirect from auth pages if already authenticated
        if (["/login", "/signup"].includes(location.pathname)) {
          navigate("/dashboard", { replace: true });
        }
      } else {
        setUser(null);
      }
    } catch (error) {
      setUser(null);
    } finally {
      if (!initialAuthCheckDone) setInitialAuthCheckDone(true);
    }
  }, [navigate, location.pathname, initialAuthCheckDone]);

  // Debounced auth check
  useEffect(() => {
    if (authCheckTimeout.current) {
      clearTimeout(authCheckTimeout.current);
    }

    authCheckTimeout.current = setTimeout(() => {
      checkAuth();
    }, 300); // 300ms debounce

    return () => {
      if (authCheckTimeout.current) {
        clearTimeout(authCheckTimeout.current);
      }
    };
  }, [checkAuth, location.pathname]);

  // Show loading only for initial auth check
  if (!initialAuthCheckDone) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  // Determine if navbar should be hidden
  const hideNavbar = /^\/[^/]+$/.test(location.pathname) && 
    !["/", "/login", "/signup"].some(route => location.pathname.startsWith(route));

  return (
    <>
      {!hideNavbar && <Navbar user={user} setUser={setUser} />}
      <Routes>
        {/* Public routes */}
        <Route path="/" element={<Home user={user} />} />
        <Route path="/login" element={
          <PublicOnlyRoute user={user}>
            <LoginPage setUser={setUser} />
          </PublicOnlyRoute>
        } />
        <Route path="/signup" element={
          <PublicOnlyRoute user={user}>
            <SignupPage />
          </PublicOnlyRoute>
        } />
        
        {/* Protected routes */}
        <Route path="/dashboard" element={
          <ProtectedRoute user={user}>
            <IndexPage />
          </ProtectedRoute>
        } />
        
        {/* Other routes */}
        <Route path="/:username" element={<PublicProfilePage />} />
      </Routes>
    </>
  );
}

export default App;