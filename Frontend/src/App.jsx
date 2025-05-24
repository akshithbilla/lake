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
//import PageNotFound from "./config/pagenotfound";
import ProtectedRoute from "./components/Layout/ProtectedRoute.tsx";
import PublicOnlyRoute from "./components/Layout/PublicOnlyRoute";

function App() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();
  const location = useLocation();

  const checkAuth = useCallback(async () => {
    try {
      const response = await axios.get(`${import.meta.env.VITE_BACKEND_URL}/check-auth`, {
        withCredentials: true,
      });
      if (response.data.authenticated) {
        setUser(response.data.user);
      } else {
        setUser(null);
      }
    } catch (error) {
      console.error("Auth check failed:", error);
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    checkAuth();
  }, [checkAuth]);

  if (loading) {
    return <div className="loader-container">Loading...</div>;
  }

  const isPublicProfileRoute = /^\/[^/]+$/.test(location.pathname); // Matches "/username"
  const knownStaticRoutes = [
    "/", "/login", "/signup", "/forgot-password", "/reset-password", "/verify-email"
  ];

  const isKnownRoute = knownStaticRoutes.some(
    (route) => location.pathname === route || location.pathname.startsWith(route + "/")
  );

  const hideNavbar = isPublicProfileRoute && !isKnownRoute;

  return (
    <>
      {!hideNavbar && <Navbar user={user} setUser={setUser} />}
      <Routes>
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
        <Route
          path="/"
          element={
            <ProtectedRoute user={user}>
              <IndexPage />
            </ProtectedRoute>
          }
        />
        <Route path="/:username" element={<PublicProfilePage />} />
       {/* *<Route path="*" element={<PageNotFound />} /> */}
      </Routes>
    </>
  );
}

export default App;
