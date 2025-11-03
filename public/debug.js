/**
 * Debug script for AuthGateway verification
 * Helps identify issues with verification process
 */

class AuthGatewayDebugger {
    constructor() {
        this.debugMode = window.location.search.includes('debug=true') || localStorage.getItem('auth_debug') === 'true';
        this.logs = [];

        if (this.debugMode) {
            this.enableDebugMode();
        }
    }

    enableDebugMode() {
        console.log('🔍 AuthGateway Debug Mode Enabled');
        this.createDebugPanel();
        this.interceptConsole();
        this.monitorNetworkRequests();
    }

    createDebugPanel() {
        // Create debug panel
        const debugPanel = document.createElement('div');
        debugPanel.id = 'auth-debug-panel';
        debugPanel.innerHTML = `
            <div class="debug-header">
                <h3>🔍 AuthGateway Debug</h3>
                <button onclick="authDebugger.clearLogs()">Clear</button>
                <button onclick="authDebugger.exportLogs()">Export</button>
                <button onclick="authDebugger.togglePanel()">Hide</button>
            </div>
            <div class="debug-content">
                <div class="debug-section">
                    <h4>System Status</h4>
                    <div id="debug-status">Checking...</div>
                </div>
                <div class="debug-section">
                    <h4>Recent Logs</h4>
                    <div id="debug-logs"></div>
                </div>
            </div>
        `;

        debugPanel.style.cssText = `
            position: fixed;
            top: 10px;
            right: 10px;
            width: 350px;
            max-height: 500px;
            background: rgba(0, 0, 0, 0.9);
            color: white;
            font-family: monospace;
            font-size: 12px;
            border: 1px solid #333;
            border-radius: 8px;
            z-index: 10001;
            overflow: hidden;
        `;

        // Add styles for debug panel
        const style = document.createElement('style');
        style.textContent = `
            #auth-debug-panel .debug-header {
                background: #333;
                padding: 10px;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }

            #auth-debug-panel .debug-header h3 {
                margin: 0;
                font-size: 14px;
            }

            #auth-debug-panel .debug-header button {
                background: #555;
                color: white;
                border: none;
                padding: 4px 8px;
                border-radius: 4px;
                cursor: pointer;
                font-size: 11px;
            }

            #auth-debug-panel .debug-content {
                padding: 10px;
                max-height: 400px;
                overflow-y: auto;
            }

            #auth-debug-panel .debug-section {
                margin-bottom: 15px;
            }

            #auth-debug-panel .debug-section h4 {
                margin: 0 0 8px 0;
                font-size: 13px;
                color: #4aff8c;
            }

            #auth-debug-panel .debug-log {
                margin-bottom: 5px;
                padding: 3px 5px;
                border-radius: 3px;
                word-break: break-word;
            }

            .debug-log.info { background: rgba(100, 149, 237, 0.2); }
            .debug-log.success { background: rgba(74, 255, 140, 0.2); }
            .debug-log.warning { background: rgba(255, 204, 102, 0.2); }
            .debug-log.error { background: rgba(255, 85, 122, 0.2); }
        `;
        document.head.appendChild(style);
        document.body.appendChild(debugPanel);

        this.updateSystemStatus();
        setInterval(() => this.updateSystemStatus(), 5000);
    }

    updateSystemStatus() {
        const statusEl = document.getElementById('debug-status');
        if (!statusEl) return;

        const status = {
            'Security Manager': window.securityManager ? '✅ Loaded' : '❌ Missing',
            'UFO Loading': window.moonUFOLoading ? '✅ Loaded' : '❌ Missing',
            'CSRF Nonce': this.getCSRFStatus(),
            'Domain': window.location.hostname,
            'User Agent': navigator.userAgent.substring(0, 50) + '...',
            'Storage': this.getStorageStatus()
        };

        statusEl.innerHTML = Object.entries(status)
            .map(([key, value]) => `<div><strong>${key}:</strong> ${value}</div>`)
            .join('');
    }

    getCSRFStatus() {
        try {
            const stored = sessionStorage.getItem('csrf_nonce');
            return stored ? '✅ Present' : '❌ Missing';
        } catch {
            return '❌ Error';
        }
    }

    getStorageStatus() {
        try {
            sessionStorage.setItem('test', 'test');
            sessionStorage.removeItem('test');
            return '✅ Available';
        } catch {
            return '❌ Disabled';
        }
    }

    interceptConsole() {
        const originalLog = console.log;
        const originalError = console.error;
        const originalWarn = console.warn;

        console.log = (...args) => {
            this.addLog('info', args.join(' '));
            originalLog.apply(console, args);
        };

        console.error = (...args) => {
            this.addLog('error', args.join(' '));
            originalError.apply(console, args);
        };

        console.warn = (...args) => {
            this.addLog('warning', args.join(' '));
            originalWarn.apply(console, args);
        };
    }

    monitorNetworkRequests() {
        const originalFetch = window.fetch;

        window.fetch = async (...args) => {
            const startTime = Date.now();
            const url = args[0];

            this.addLog('info', `🌐 Request: ${url}`);

            try {
                const response = await originalFetch.apply(window, args);
                const duration = Date.now() - startTime;

                this.addLog(response.ok ? 'success' : 'error',
                    `📡 Response: ${response.status} (${duration}ms) - ${url}`);

                return response;
            } catch (error) {
                const duration = Date.now() - startTime;
                this.addLog('error', `❌ Failed: ${error.message} (${duration}ms) - ${url}`);
                throw error;
            }
        };
    }

    addLog(level, message) {
        const timestamp = new Date().toLocaleTimeString();
        this.logs.push({ timestamp, level, message });

        // Keep only last 50 logs
        if (this.logs.length > 50) {
            this.logs.shift();
        }

        this.updateLogsDisplay();
    }

    updateLogsDisplay() {
        const logsEl = document.getElementById('debug-logs');
        if (!logsEl) return;

        logsEl.innerHTML = this.logs
            .slice(-20) // Show last 20 logs
            .map(log => `
                <div class="debug-log ${log.level}">
                    [${log.timestamp}] ${log.message}
                </div>
            `).join('');

        // Auto-scroll to bottom
        logsEl.scrollTop = logsEl.scrollHeight;
    }

    clearLogs() {
        this.logs = [];
        this.updateLogsDisplay();
    }

    exportLogs() {
        const logData = {
            timestamp: new Date().toISOString(),
            url: window.location.href,
            userAgent: navigator.userAgent,
            logs: this.logs
        };

        const blob = new Blob([JSON.stringify(logData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `authgateway-debug-${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
    }

    togglePanel() {
        const panel = document.getElementById('auth-debug-panel');
        if (panel) {
            panel.style.display = panel.style.display === 'none' ? 'block' : 'none';
        }
    }

    // Public methods for manual debugging
    logStep(step, message, level = 'info') {
        this.addLog(level, `🔧 ${step}: ${message}`);
    }

    logVerificationStart() {
        this.logStep('Verification', 'Starting verification process', 'info');
    }

    logVerificationSuccess(data) {
        this.logStep('Verification', `Success: ${JSON.stringify(data)}`, 'success');
    }

    logVerificationError(error) {
        this.logStep('Verification', `Error: ${error.message}`, 'error');
    }
}

// Initialize debugger
const authDebugger = new AuthGatewayDebugger();

// Make it globally available
window.authDebugger = authDebugger;

// Add debugging shortcuts
document.addEventListener('keydown', (e) => {
    // Ctrl+Shift+D to toggle debug mode
    if (e.ctrlKey && e.shiftKey && e.key === 'D') {
        e.preventDefault();
        localStorage.setItem('auth_debug', localStorage.getItem('auth_debug') === 'true' ? 'false' : 'true');
        location.reload();
    }
});

// Add verification debugging
if (window.location.search.includes('debug=true')) {
    // Intercept verification form submission
    document.addEventListener('DOMContentLoaded', () => {
        const form = document.getElementById('verificationForm');
        if (form) {
            form.addEventListener('submit', (e) => {
                authDebugger.logVerificationStart();
            });
        }
    });
}