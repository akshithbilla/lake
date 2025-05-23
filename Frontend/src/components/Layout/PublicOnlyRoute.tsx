// components/Layout/PublicOnlyRoute.tsx
import { Navigate } from 'react-router-dom';

type PublicOnlyRouteProps = {
  user: any;
  children: JSX.Element;
  redirectPath?: string;
};

const PublicOnlyRoute = ({ user, children, redirectPath = "/dash" }: PublicOnlyRouteProps) => {
  if (user) {
    return <Navigate to={redirectPath} replace />;
  }

  return children;
};

export default PublicOnlyRoute;
