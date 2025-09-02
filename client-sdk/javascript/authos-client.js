/**
 * AuthOS JavaScript Client SDK
 * 
 * Client-side SDK for integrating with AuthOS SSO authentication service
 */
class AuthosClient {
    constructor(config) {
        this.authosUrl = config.authosUrl.replace(/\/$/, '');
        this.applicationId = config.applicationId;
        this.allowedDomains = config.allowedDomains || [];
        this.callbackUrl = config.callbackUrl;
        this.logoutUrl = config.logoutUrl;
        this.storagePrefix = config.storagePrefix || 'authos_';
        this.storage = config.storage || localStorage;
        
        // Event listeners
        this.onLoginSuccess = config.onLoginSuccess || (() => {});
        this.onLoginError = config.onLoginError || ((error) => console.error('AuthOS Login Error:', error));
        this.onLogout = config.onLogout || (() => {});
    }

    /**
     * Initiate SSO login flow
     */
    initiateLogin(redirectUri = null) {
        const redirect = redirectUri || this.callbackUrl;
        const state = this.generateState();
        
        // Store state for validation
        this.storage.setItem(this.storagePrefix + 'state', state);
        this.storage.setItem(this.storagePrefix + 'redirect_uri', redirect);
        
        const params = new URLSearchParams({
            application_id: this.applicationId,
            redirect_uri: redirect,
            response_type: 'code',
            state: state
        });

        const loginUrl = `${this.authosUrl}/api/v1/sso/initiate?${params}`;
        window.location.href = loginUrl;
    }

    /**
     * Handle callback and exchange code for tokens
     */
    async handleCallback() {
        const urlParams = new URLSearchParams(window.location.search);
        const code = urlParams.get('code');
        const state = urlParams.get('state');
        const error = urlParams.get('error');

        if (error) {
            this.onLoginError(error);
            return null;
        }

        // Validate state parameter
        const storedState = this.storage.getItem(this.storagePrefix + 'state');
        if (!state || state !== storedState) {
            this.onLoginError('Invalid state parameter');
            return null;
        }

        if (!code) {
            this.onLoginError('No authorization code received');
            return null;
        }

        try {
            const response = await this.makeRequest('POST', '/api/v1/sso/callback', {
                code: code,
                application_id: this.applicationId,
                redirect_uri: this.storage.getItem(this.storagePrefix + 'redirect_uri')
            });

            if (!response.success) {
                this.onLoginError(response.message || 'Failed to exchange code for tokens');
                return null;
            }

            // Store tokens
            this.setTokens(response.data);

            // Clean up temporary data
            this.storage.removeItem(this.storagePrefix + 'state');
            this.storage.removeItem(this.storagePrefix + 'redirect_uri');

            // Clear URL parameters
            window.history.replaceState({}, document.title, window.location.pathname);

            this.onLoginSuccess(response.data);
            return response.data;

        } catch (error) {
            this.onLoginError(error.message);
            return null;
        }
    }

    /**
     * Validate current session
     */
    async validateSession() {
        const accessToken = this.getAccessToken();
        
        if (!accessToken) {
            return null;
        }

        try {
            const response = await this.makeRequest('POST', '/api/v1/sso/validate', {
                token: accessToken
            });

            if (!response.success) {
                // Try to refresh token
                return await this.refreshSession();
            }

            return response.data;

        } catch (error) {
            // Try to refresh token on error
            return await this.refreshSession();
        }
    }

    /**
     * Refresh session token
     */
    async refreshSession() {
        const refreshToken = this.getRefreshToken();
        
        if (!refreshToken) {
            this.clearSession();
            return null;
        }

        try {
            const response = await this.makeRequest('POST', '/api/v1/sso/refresh', {
                refresh_token: refreshToken
            });

            if (!response.success) {
                this.clearSession();
                return null;
            }

            // Update stored tokens
            this.setTokens(response.data);
            return response.data;

        } catch (error) {
            this.clearSession();
            return null;
        }
    }

    /**
     * Logout user and synchronize across applications
     */
    async logout() {
        const accessToken = this.getAccessToken();
        
        if (!accessToken) {
            this.clearSession();
            this.onLogout();
            return { success: true, logout_urls: [] };
        }

        try {
            const response = await this.makeRequest('POST', '/api/v1/sso/logout', {
                token: accessToken
            });

            // Clear local session regardless of API response
            this.clearSession();
            this.onLogout();

            // Handle logout URLs if provided
            if (response.data && response.data.logout_urls) {
                this.handleLogoutUrls(response.data.logout_urls);
            }

            return response;

        } catch (error) {
            // Clear local session even on error
            this.clearSession();
            this.onLogout();
            throw error;
        }
    }

    /**
     * Get current user information
     */
    getUser() {
        const userData = this.storage.getItem(this.storagePrefix + 'user');
        return userData ? JSON.parse(userData) : null;
    }

    /**
     * Check if user is authenticated
     */
    async isAuthenticated() {
        const session = await this.validateSession();
        return session !== null;
    }

    /**
     * Get access token
     */
    getAccessToken() {
        return this.storage.getItem(this.storagePrefix + 'access_token');
    }

    /**
     * Get refresh token
     */
    getRefreshToken() {
        return this.storage.getItem(this.storagePrefix + 'refresh_token');
    }

    /**
     * Set authentication tokens
     */
    setTokens(data) {
        this.storage.setItem(this.storagePrefix + 'access_token', data.access_token);
        this.storage.setItem(this.storagePrefix + 'refresh_token', data.refresh_token);
        
        if (data.user) {
            this.storage.setItem(this.storagePrefix + 'user', JSON.stringify(data.user));
        }
        
        if (data.expires_in) {
            const expiresAt = Date.now() + (data.expires_in * 1000);
            this.storage.setItem(this.storagePrefix + 'expires_at', expiresAt.toString());
        }
    }

    /**
     * Clear session data
     */
    clearSession() {
        const keys = ['access_token', 'refresh_token', 'user', 'expires_at', 'state', 'redirect_uri'];
        keys.forEach(key => {
            this.storage.removeItem(this.storagePrefix + key);
        });
    }

    /**
     * Add authorization header to requests
     */
    getAuthHeader() {
        const token = this.getAccessToken();
        return token ? { 'Authorization': `Bearer ${token}` } : {};
    }

    /**
     * Make authenticated request
     */
    async makeAuthenticatedRequest(method, endpoint, data = null) {
        const headers = {
            ...this.getAuthHeader(),
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        };

        return await this.makeRequest(method, endpoint, data, headers);
    }

    /**
     * Auto-refresh token wrapper
     */
    async withAutoRefresh(callback) {
        try {
            return await callback();
        } catch (error) {
            if (error.status === 401) {
                // Try to refresh and retry
                const refreshed = await this.refreshSession();
                if (refreshed) {
                    return await callback();
                }
            }
            throw error;
        }
    }

    /**
     * Handle logout URLs from other applications
     */
    handleLogoutUrls(logoutUrls) {
        // Create hidden iframes to trigger logout on other applications
        logoutUrls.forEach(url => {
            const iframe = document.createElement('iframe');
            iframe.style.display = 'none';
            iframe.src = url;
            document.body.appendChild(iframe);
            
            // Remove iframe after a short delay
            setTimeout(() => {
                document.body.removeChild(iframe);
            }, 2000);
        });
    }

    /**
     * Generate cryptographically secure state parameter
     */
    generateState() {
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    }

    /**
     * Make HTTP request
     */
    async makeRequest(method, endpoint, data = null, customHeaders = {}) {
        const url = this.authosUrl + endpoint;
        
        const headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            ...customHeaders
        };

        const options = {
            method: method,
            headers: headers,
            credentials: 'include'
        };

        if (data && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
            options.body = JSON.stringify(data);
        }

        const response = await fetch(url, options);
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.message || `HTTP ${response.status}`);
        }

        return await response.json();
    }

    /**
     * Initialize the client and handle callback if present
     */
    async init() {
        // Check if this is a callback URL
        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.has('code') || urlParams.has('error')) {
            return await this.handleCallback();
        }

        // Validate existing session
        return await this.validateSession();
    }
}

// Export for different module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = AuthosClient;
} else if (typeof define === 'function' && define.amd) {
    define([], function() { return AuthosClient; });
} else if (typeof window !== 'undefined') {
    window.AuthosClient = AuthosClient;
}

/* Usage Example:

// Initialize client
const authos = new AuthosClient({
    authosUrl: 'https://auth.yourapp.com',
    applicationId: 1,
    callbackUrl: 'https://yourapp.com/auth/callback',
    logoutUrl: 'https://yourapp.com/logout',
    allowedDomains: ['yourapp.com'],
    onLoginSuccess: (data) => {
        console.log('Login successful:', data);
        // Redirect or update UI
    },
    onLoginError: (error) => {
        console.error('Login failed:', error);
        // Show error message
    },
    onLogout: () => {
        console.log('User logged out');
        // Redirect to home page
    }
});

// Initialize and handle callback
authos.init().then(session => {
    if (session) {
        console.log('User is authenticated:', session);
    }
});

// Login button
document.getElementById('login-btn').addEventListener('click', () => {
    authos.initiateLogin();
});

// Logout button
document.getElementById('logout-btn').addEventListener('click', async () => {
    await authos.logout();
});

// Check authentication status
authos.isAuthenticated().then(isAuth => {
    if (isAuth) {
        const user = authos.getUser();
        document.getElementById('user-name').textContent = user.name;
    }
});

// Make authenticated requests
authos.makeAuthenticatedRequest('GET', '/api/v1/profile')
    .then(response => {
        console.log('Profile:', response);
    });

*/