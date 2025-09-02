/**
 * React Integration Example with AuthOS
 * 
 * This example shows how to integrate AuthOS SSO with a React application
 */

import React, { createContext, useContext, useEffect, useState } from 'react';
import AuthosClient from '../javascript/authos-client.js';

// 1. Create AuthOS Context
const AuthosContext = createContext(null);

// 2. AuthOS Provider Component
export const AuthosProvider = ({ children, config }) => {
  const [authos] = useState(() => new AuthosClient({
    ...config,
    onLoginSuccess: (data) => {
      console.log('Login successful:', data);
      setUser(data.user);
      setIsAuthenticated(true);
    },
    onLoginError: (error) => {
      console.error('Login failed:', error);
      setError(error);
      setIsAuthenticated(false);
    },
    onLogout: () => {
      console.log('User logged out');
      setUser(null);
      setIsAuthenticated(false);
    }
  }));

  const [user, setUser] = useState(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    // Initialize AuthOS and check authentication status
    const initialize = async () => {
      try {
        setLoading(true);
        setError(null);
        
        // Handle callback or validate existing session
        const session = await authos.init();
        
        if (session) {
          setUser(session.user || authos.getUser());
          setIsAuthenticated(true);
        } else {
          setUser(null);
          setIsAuthenticated(false);
        }
      } catch (err) {
        console.error('AuthOS initialization error:', err);
        setError(err.message);
        setIsAuthenticated(false);
      } finally {
        setLoading(false);
      }
    };

    initialize();
  }, [authos]);

  const value = {
    authos,
    user,
    isAuthenticated,
    loading,
    error,
    login: (redirectUri) => authos.initiateLogin(redirectUri),
    logout: () => authos.logout(),
    clearError: () => setError(null)
  };

  return (
    <AuthosContext.Provider value={value}>
      {children}
    </AuthosContext.Provider>
  );
};

// 3. Custom Hook for using AuthOS
export const useAuthos = () => {
  const context = useContext(AuthosContext);
  if (!context) {
    throw new Error('useAuthos must be used within an AuthosProvider');
  }
  return context;
};

// 4. Higher-Order Component for protecting routes
export const withAuthosAuth = (Component) => {
  return function AuthosProtectedComponent(props) {
    const { isAuthenticated, loading, login } = useAuthos();

    if (loading) {
      return <div>Loading...</div>;
    }

    if (!isAuthenticated) {
      return (
        <div className="auth-required">
          <h2>Authentication Required</h2>
          <p>You need to sign in to access this page.</p>
          <button onClick={() => login()}>
            Sign in with AuthOS
          </button>
        </div>
      );
    }

    return <Component {...props} />;
  };
};

// 5. Login Component
export const LoginPage = () => {
  const { login, loading, error, clearError } = useAuthos();

  return (
    <div className="login-page">
      <div className="login-card">
        <h2>Sign In</h2>
        <p>Sign in with your organizational account</p>
        
        {error && (
          <div className="error-message">
            <p>{error}</p>
            <button onClick={clearError}>Dismiss</button>
          </div>
        )}
        
        <button 
          onClick={() => login()} 
          disabled={loading}
          className="login-button"
        >
          {loading ? 'Signing in...' : 'Sign in with AuthOS'}
        </button>
      </div>
    </div>
  );
};

// 6. User Profile Component
export const UserProfile = () => {
  const { user, logout, loading } = useAuthos();

  if (!user) return null;

  return (
    <div className="user-profile">
      <div className="profile-header">
        <h3>Welcome, {user.name}</h3>
        <button 
          onClick={logout} 
          disabled={loading}
          className="logout-button"
        >
          {loading ? 'Signing out...' : 'Sign out'}
        </button>
      </div>
      <div className="profile-info">
        <p><strong>Email:</strong> {user.email}</p>
        <p><strong>Organization:</strong> {user.organization_id}</p>
      </div>
    </div>
  );
};

// 7. Protected Dashboard Component
const Dashboard = withAuthosAuth(() => {
  const { user } = useAuthos();

  return (
    <div className="dashboard">
      <h1>Dashboard</h1>
      <UserProfile />
      
      <div className="dashboard-content">
        <h2>Your Account</h2>
        <p>This is a protected page that requires authentication.</p>
        
        {/* Your protected content here */}
      </div>
    </div>
  );
});

// 8. Main App Component
export const App = () => {
  const { isAuthenticated, loading, error } = useAuthos();

  if (loading) {
    return (
      <div className="app-loading">
        <div className="spinner"></div>
        <p>Loading...</p>
      </div>
    );
  }

  return (
    <div className="app">
      <header className="app-header">
        <h1>My App</h1>
        {isAuthenticated ? <UserProfile /> : null}
      </header>
      
      <main className="app-content">
        {error && (
          <div className="app-error">
            <p>Error: {error}</p>
          </div>
        )}
        
        {isAuthenticated ? <Dashboard /> : <LoginPage />}
      </main>
    </div>
  );
};

// 9. Hook for making authenticated API calls
export const useAuthosAPI = () => {
  const { authos } = useAuthos();

  const apiCall = async (method, endpoint, data = null) => {
    return await authos.withAutoRefresh(async () => {
      return await authos.makeAuthenticatedRequest(method, endpoint, data);
    });
  };

  return {
    get: (endpoint) => apiCall('GET', endpoint),
    post: (endpoint, data) => apiCall('POST', endpoint, data),
    put: (endpoint, data) => apiCall('PUT', endpoint, data),
    delete: (endpoint) => apiCall('DELETE', endpoint),
  };
};

// 10. Example of using the API hook
export const UserSettings = withAuthosAuth(() => {
  const api = useAuthosAPI();
  const [settings, setSettings] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadSettings = async () => {
      try {
        const response = await api.get('/api/v1/profile');
        setSettings(response.data);
      } catch (error) {
        console.error('Failed to load settings:', error);
      } finally {
        setLoading(false);
      }
    };

    loadSettings();
  }, [api]);

  const saveSettings = async (newSettings) => {
    try {
      setLoading(true);
      const response = await api.put('/api/v1/profile', newSettings);
      setSettings(response.data);
    } catch (error) {
      console.error('Failed to save settings:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <div>Loading settings...</div>;

  return (
    <div className="user-settings">
      <h2>User Settings</h2>
      {/* Settings form here */}
    </div>
  );
});

// 11. Root component with AuthOS provider
export const AppRoot = () => {
  const authosConfig = {
    authosUrl: process.env.REACT_APP_AUTHOS_URL || 'https://auth.yourapp.com',
    applicationId: parseInt(process.env.REACT_APP_AUTHOS_APP_ID),
    callbackUrl: `${window.location.origin}/auth/callback`,
    logoutUrl: `${window.location.origin}/logout`,
    allowedDomains: (process.env.REACT_APP_AUTHOS_ALLOWED_DOMAINS || '').split(','),
  };

  return (
    <AuthosProvider config={authosConfig}>
      <App />
    </AuthosProvider>
  );
};

export default AppRoot;

/* 
Usage in index.js:

import React from 'react';
import ReactDOM from 'react-dom/client';
import AppRoot from './AppRoot';
import './index.css';

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <AppRoot />
  </React.StrictMode>
);

*/

/* 
Environment Variables (.env):

REACT_APP_AUTHOS_URL=https://your-authos-instance.com
REACT_APP_AUTHOS_APP_ID=1
REACT_APP_AUTHOS_ALLOWED_DOMAINS=yourapp.com,*.yourapp.com

*/

/* 
CSS Styles (index.css):

.app-loading {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 100vh;
}

.spinner {
  border: 4px solid #f3f3f3;
  border-top: 4px solid #3498db;
  border-radius: 50%;
  width: 40px;
  height: 40px;
  animation: spin 2s linear infinite;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

.login-page {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100vh;
  background-color: #f5f5f5;
}

.login-card {
  background: white;
  padding: 2rem;
  border-radius: 8px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
  max-width: 400px;
  width: 100%;
}

.login-button {
  background-color: #007bff;
  color: white;
  border: none;
  padding: 12px 24px;
  border-radius: 4px;
  cursor: pointer;
  width: 100%;
  font-size: 16px;
}

.login-button:hover {
  background-color: #0056b3;
}

.login-button:disabled {
  background-color: #6c757d;
  cursor: not-allowed;
}

.error-message {
  background-color: #f8d7da;
  color: #721c24;
  padding: 12px;
  border-radius: 4px;
  margin-bottom: 16px;
}

.user-profile {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 1rem;
  background-color: #f8f9fa;
  border-radius: 4px;
}

.logout-button {
  background-color: #dc3545;
  color: white;
  border: none;
  padding: 8px 16px;
  border-radius: 4px;
  cursor: pointer;
}

.logout-button:hover {
  background-color: #c82333;
}

*/