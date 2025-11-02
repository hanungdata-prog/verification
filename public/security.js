/**
 * Security module for AuthGateway frontend
 * Handles CSRF protection, domain validation, and security monitoring
 */

class SecurityManager {
    constructor() {
        this.csrfNonce = null;
        this.sessionId = null;
        this.isInitialized = false;
        this.securityChecks = {
            domainValid: false,
            vpnBlocked: false,
            suspiciousActivity: false
        };
    }

    async initialize() {
        try {
            // Check if domain is allowed
            this.validateDomain();

            // Get CSRF nonce
            await this.fetchCSRFNonce();

            // Initialize security monitoring
            this.initializeSecurityMonitoring();

            this.isInitialized = true;
            console.log('SecurityManager initialized successfully');
        } catch (error) {
            console.error('Failed to initialize SecurityManager:', error);
            this.handleSecurityError('Security initialization failed');
        }
    }

    validateDomain() {
        const currentDomain = window.location.hostname;
        const allowedDomains = [
            'authgateway.vercel.app',
            'localhost',
            '127.0.0.1'
        ];

        const isAllowed = allowedDomains.some(domain => {
            if (domain.includes('*')) {
                const regex = new RegExp(domain.replace(/\*/g, '.*'));
                return regex.test(currentDomain);
            }
            return currentDomain === domain || currentDomain.endsWith(`.${domain}`);
        });

        if (!isAllowed) {
            this.handleSecurityError(`Domain ${currentDomain} is not allowed`);
            return;
        }

        this.securityChecks.domainValid = true;
    }

    async fetchCSRFNonce() {
        try {
            const response = await fetch('/api/csrf-nonce', {
                method: 'GET',
                credentials: 'include',
                headers: {
                    'Accept': 'application/json'
                }
            });

            if (!response.ok) {
                throw new Error(`Failed to fetch CSRF nonce: ${response.status}`);
            }

            const data = await response.json();
            this.csrfNonce = data.nonce;
            this.sessionId = data.session_id;

            // Store nonce securely
            this.storeNonceSecurely();
        } catch (error) {
            console.error('Failed to fetch CSRF nonce:', error);
            throw error;
        }
    }

    storeNonceSecurely() {
        // Use sessionStorage for nonce (not localStorage for security)
        try {
            sessionStorage.setItem('csrf_nonce', this.csrfNonce);
            sessionStorage.setItem('session_id', this.sessionId);
        } catch (error) {
            console.error('Failed to store nonce securely:', error);
        }
    }

    getStoredNonce() {
        try {
            return {
                nonce: sessionStorage.getItem('csrf_nonce'),
                sessionId: sessionStorage.getItem('session_id')
            };
        } catch (error) {
            console.error('Failed to retrieve stored nonce:', error);
            return { nonce: null, sessionId: null };
        }
    }

    async verifyRequest(data) {
        if (!this.isInitialized) {
            await this.initialize();
        }

        const stored = this.getStoredNonce();

        if (!stored.nonce || !stored.sessionId) {
            throw new Error('CSRF nonce not available');
        }

        // Add security headers and nonce to request
        const secureData = {
            ...data,
            csrf_nonce: stored.nonce,
            security_metadata: {
                timestamp: Date.now(),
                user_agent: navigator.userAgent,
                domain: window.location.hostname,
                referrer: document.referrer
            }
        };

        return secureData;
    }

    async secureFetch(url, options = {}) {
        const secureOptions = {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest',
                ...options.headers
            },
            credentials: 'include',
            mode: 'same-origin'
        };

        // Add CSRF token to headers if available
        const stored = this.getStoredNonce();
        if (stored.nonce) {
            secureOptions.headers['X-CSRF-Token'] = stored.nonce;
        }

        try {
            const response = await fetch(url, secureOptions);

            // Handle security-related responses
            if (response.status === 403) {
                const error = await response.json();
                this.handleSecurityError(error.detail || 'Access denied');
                throw new Error('Security check failed');
            }

            if (response.status === 429) {
                this.handleRateLimit();
                throw new Error('Rate limit exceeded');
            }

            return response;
        } catch (error) {
            if (error.message !== 'Security check failed' &&
                error.message !== 'Rate limit exceeded') {
                console.error('Secure fetch failed:', error);
            }
            throw error;
        }
    }

    initializeSecurityMonitoring() {
        // Monitor for suspicious activities
        this.monitorRapidRequests();
        this.monitorConsoleAccess();
        this.monitorDeveloperTools();
    }

    monitorRapidRequests() {
        const requestTimes = [];
        const MAX_REQUESTS_PER_MINUTE = 30;
        const MINUTE = 60000;

        // Override fetch to monitor requests
        const originalFetch = window.fetch;
        window.fetch = async (...args) => {
            const now = Date.now();

            // Clean old requests
            const recentRequests = requestTimes.filter(time => now - time < MINUTE);
            requestTimes.length = 0;
            requestTimes.push(...recentRequests);

            // Add current request
            requestTimes.push(now);

            // Check for suspicious activity
            if (requestTimes.length > MAX_REQUESTS_PER_MINUTE) {
                this.handleSuspiciousActivity('Too many requests');
                return Promise.reject(new Error('Rate limit exceeded'));
            }

            return originalFetch.apply(this, args);
        };
    }

    monitorConsoleAccess() {
        let consoleAccessCount = 0;
        const MAX_CONSOLE_ACCESS = 10;

        const originalLog = console.log;
        const originalWarn = console.warn;
        const originalError = console.error;

        const monitorConsole = (originalMethod) => {
            return (...args) => {
                consoleAccessCount++;

                if (consoleAccessCount > MAX_CONSOLE_ACCESS) {
                    this.handleSuspiciousActivity('Excessive console access');
                }

                return originalMethod.apply(console, args);
            };
        };

        console.log = monitorConsole(originalLog);
        console.warn = monitorConsole(originalWarn);
        console.error = monitorConsole(originalError);
    }

    monitorDeveloperTools() {
        let devtoolsOpen = false;

        const checkDevTools = () => {
            const threshold = 160;
            if (window.outerHeight - window.innerHeight > threshold ||
                window.outerWidth - window.innerWidth > threshold) {
                if (!devtoolsOpen) {
                    devtoolsOpen = true;
                    this.handleSuspiciousActivity('Developer tools opened');
                }
            } else {
                devtoolsOpen = false;
            }
        };

        setInterval(checkDevTools, 1000);
    }

    handleSecurityError(message) {
        console.error('Security Error:', message);

        // Show user-friendly error message
        this.showSecurityMessage(message, 'error');

        // Optionally redirect to safety page
        setTimeout(() => {
            if (message.includes('Domain')) {
                window.location.href = '/security-error.html?reason=domain';
            } else if (message.includes('VPN') || message.includes('Proxy')) {
                window.location.href = '/security-error.html?reason=vpn';
            } else {
                window.location.href = '/security-error.html?reason=general';
            }
        }, 3000);
    }

    handleRateLimit() {
        this.showSecurityMessage('Too many requests. Please wait a moment.', 'warning');
    }

    handleSuspiciousActivity(activity) {
        console.warn('Suspicious activity detected:', activity);
        this.securityChecks.suspiciousActivity = true;

        // Log to server for monitoring
        this.logSuspiciousActivity(activity);
    }

    async logSuspiciousActivity(activity) {
        try {
            await this.secureFetch('/api/log-suspicious-activity', {
                method: 'POST',
                body: JSON.stringify({
                    activity,
                    timestamp: Date.now(),
                    user_agent: navigator.userAgent,
                    domain: window.location.hostname
                })
            });
        } catch (error) {
            console.error('Failed to log suspicious activity:', error);
        }
    }

    showSecurityMessage(message, type = 'error') {
        // Remove existing messages
        const existingMessage = document.querySelector('.security-message');
        if (existingMessage) {
            existingMessage.remove();
        }

        // Create new message
        const messageElement = document.createElement('div');
        messageElement.className = `security-message security-${type}`;
        messageElement.innerHTML = `
            <div class="security-content">
                <i class="fas fa-${type === 'error' ? 'exclamation-triangle' : 'info-circle'}"></i>
                <span>${message}</span>
            </div>
        `;

        // Add styles
        messageElement.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            left: 20px;
            background: ${type === 'error' ? '#ff557a' : '#ffcc66'};
            color: white;
            padding: 15px;
            border-radius: 8px;
            z-index: 10000;
            font-family: Inter, sans-serif;
            font-size: 14px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            animation: slideIn 0.3s ease-out;
        `;

        // Add animation
        const style = document.createElement('style');
        style.textContent = `
            @keyframes slideIn {
                from { transform: translateY(-100%); opacity: 0; }
                to { transform: translateY(0); opacity: 1; }
            }
            .security-content {
                display: flex;
                align-items: center;
                gap: 10px;
            }
        `;
        document.head.appendChild(style);

        document.body.appendChild(messageElement);

        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (messageElement.parentNode) {
                messageElement.remove();
            }
        }, 5000);
    }

    // VPN Detection (frontend heuristic)
    async detectVPN() {
        try {
            // Check for common VPN indicators
            const indicators = {
                timezoneMismatch: this.checkTimezoneMismatch(),
                navigatorProperties: this.checkNavigatorProperties(),
                screenResolution: this.checkScreenResolution(),
                webdriver: this.checkWebdriver()
            };

            const vpnScore = Object.values(indicators).filter(Boolean).length;

            if (vpnScore >= 2) {
                this.securityChecks.vpnBlocked = true;
                this.handleSecurityError('VPN or proxy detected');
                return true;
            }

            return false;
        } catch (error) {
            console.error('VPN detection failed:', error);
            return false;
        }
    }

    checkTimezoneMismatch() {
        // Check if timezone matches IP-based timezone
        const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
        const browserLanguage = navigator.language;

        // Simple heuristic - can be enhanced with IP-based timezone detection
        return !timezone || !browserLanguage;
    }

    checkNavigatorProperties() {
        // Check for suspicious navigator properties
        const suspiciousProps = [
            'webdriver',
            'callPhantom',
            '_phantom'
        ];

        return suspiciousProps.some(prop => navigator[prop]);
    }

    checkScreenResolution() {
        // Check for unusual screen resolutions (common with VMs/proxies)
        const width = screen.width;
        const height = screen.height;

        // Common VM resolutions
        const suspiciousResolutions = [
            [800, 600],
            [1024, 768],
            [1152, 864],
            [1280, 720]
        ];

        return suspiciousResolutions.some(([w, h]) => width === w && height === h);
    }

    checkWebdriver() {
        // Check for webdriver automation
        return navigator.webdriver ||
               window.phantom ||
               window.callPhantom ||
               window._phantom;
    }

    // Public API
    async isSecure() {
        if (!this.isInitialized) {
            await this.initialize();
        }

        return Object.values(this.securityChecks).every(check => check === true || check === false);
    }

    getSecurityStatus() {
        return {
            ...this.securityChecks,
            initialized: this.isInitialized,
            hasNonce: !!this.getStoredNonce().nonce
        };
    }
}

// Initialize security manager
const securityManager = new SecurityManager();

// Auto-initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => securityManager.initialize());
} else {
    securityManager.initialize();
}

// Export for global access
window.securityManager = securityManager;