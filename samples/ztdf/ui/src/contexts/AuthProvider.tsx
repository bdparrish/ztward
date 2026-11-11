import React, { useEffect, useState, useCallback, useMemo } from 'react';
import type { KeycloakTokenParsed } from 'keycloak-js';
import keycloak from '../config/keycloak';
import { AuthContext, type AuthUser } from './AuthContext';

// Custom claims this app reads from the Keycloak access token.
interface TokenClaims extends KeycloakTokenParsed {
  email?: string;
  name?: string;
  preferred_username?: string;
  department?: string;
  role?: 'admin' | 'editor' | 'viewer';
}

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [user, setUser] = useState<AuthUser | null>(null);
  const [token, setToken] = useState<string | null>(null);

  const updateUserFromToken = useCallback(() => {
    if (keycloak.tokenParsed) {
      const tokenData = keycloak.tokenParsed as TokenClaims;
      setUser({
        id: tokenData.sub || '',
        email: tokenData.email || '',
        name: tokenData.name || tokenData.preferred_username || '',
        department: tokenData.department || '',
        role: tokenData.role || 'viewer',
      });
    }
  }, []);

  const logout = useCallback(() => {
    setUser(null);
    setToken(null);
    setIsAuthenticated(false);
    keycloak.logout();
  }, []);

  const initKeycloak = useCallback(async () => {
    try {
      const authenticated = await keycloak.init({
        onLoad: 'check-sso',
        silentCheckSsoRedirectUri: window.location.origin + '/silent-check-sso.html',
        pkceMethod: 'S256',
      });

      setIsAuthenticated(authenticated);

      if (authenticated) {
        updateUserFromToken();
        setToken(keycloak.token || null);

        // Setup token refresh
        keycloak.onTokenExpired = () => {
          keycloak.updateToken(30).then((refreshed) => {
            if (refreshed) {
              setToken(keycloak.token || null);
              console.log('Token refreshed');
            }
          }).catch(() => {
            console.error('Failed to refresh token');
            logout();
          });
        };
      }
    } catch (error) {
      console.error('Failed to initialize Keycloak:', error);
    } finally {
      setIsLoading(false);
    }
  }, [updateUserFromToken, logout]);

  useEffect(() => {
    initKeycloak();
  }, [initKeycloak]);

  const login = useCallback(() => {
    keycloak.login();
  }, []);

  const contextValue = useMemo(() => ({
    isAuthenticated,
    isLoading,
    user,
    token,
    login,
    logout,
  }), [isAuthenticated, isLoading, user, token, login, logout]);

  return (
    <AuthContext.Provider value={contextValue}>
      {children}
    </AuthContext.Provider>
  );
};
