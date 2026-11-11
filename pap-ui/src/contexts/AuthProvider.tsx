import { useEffect, useState, ReactNode } from 'react';
import Keycloak from 'keycloak-js';
import { keycloakConfig } from '@/config/keycloak';
import { useToast } from '@/hooks/use-toast';
import { initializeApiClient } from '@/lib/api-client';
import { AuthContext } from './AuthContext';

// keycloak-js 26 needs the Web Crypto API (secure context: HTTPS or localhost) and only supports S256 PKCE.
const hasWebCrypto = () => {
  if (typeof window === 'undefined') {
    return true;
  }

  const hasSubtleCrypto = Boolean(window.crypto?.subtle);
  const secureContext = typeof window.isSecureContext === 'boolean' ? window.isSecureContext : true;

  return hasSubtleCrypto && secureContext;
};

export const AuthProvider = ({ children }: { children: ReactNode }) => {
  const [keycloak, setKeycloak] = useState<Keycloak | null>(null);
  const [authenticated, setAuthenticated] = useState(false);
  const [loading, setLoading] = useState(true);
  const { toast } = useToast();

  useEffect(() => {
    const initKeycloak = async () => {
      const keycloakInstance = new Keycloak(keycloakConfig);
      if (!hasWebCrypto()) {
        console.warn('Web Crypto API not available. Serve the PAP UI over HTTPS or localhost to sign in.');
        toast({
          title: 'Insecure Context Detected',
          description:
            'Sign-in needs the Web Crypto API, which browsers only provide over HTTPS or on localhost.',
          variant: 'destructive',
        });
      }

      try {
        const authenticated = await keycloakInstance.init({
          onLoad: 'check-sso',
          checkLoginIframe: false,
          pkceMethod: 'S256',
        });

        setKeycloak(keycloakInstance);
        setAuthenticated(authenticated);

        // Initialize API client when Keycloak is authenticated
        if (authenticated) {
          initializeApiClient(keycloakInstance);
        }
      } catch (error) {
        console.error('Keycloak initialization failed:', error);
        toast({
          title: 'Authentication Error',
          description: 'Failed to initialize authentication. Please check Keycloak configuration.',
          variant: 'destructive',
        });
      } finally {
        setLoading(false);
      }
    };

    initKeycloak();
  }, [toast]);

  const login = () => {
    keycloak?.login();
  };

  const logout = () => {
    keycloak?.logout();
  };

  const getUsername = () => {
    return keycloak?.tokenParsed?.preferred_username || 'Unknown User';
  };

  return (
    <AuthContext.Provider
      value={{
        keycloak,
        authenticated,
        loading,
        login,
        logout,
        getUsername,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};
