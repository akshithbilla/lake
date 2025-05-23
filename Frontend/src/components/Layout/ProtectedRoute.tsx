// components/Layout/ProtectedRoute.tsx
import { Navigate } from 'react-router-dom';

type ProtectedRouteProps = {
  user: any;
  children: JSX.Element;
  redirectPath?: string;
};

const ProtectedRoute = ({ user, children, redirectPath = "/login" }: ProtectedRouteProps) => {
  if (!user) {
    return <Navigate to={redirectPath} replace />;
  }

  return children;
};

export default ProtectedRoute;
