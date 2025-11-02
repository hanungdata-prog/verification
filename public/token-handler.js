/**
 * Token Handler for Discord Authentication
 * Manages secure token-based Discord user information
 */

class TokenHandler {
    constructor() {
        this.cache = new Map();
        this.cacheTimeout = 5 * 60 * 1000; // 5 minutes
    }

    /**
     * Decode Discord token to get user information
     * @param {string} token - The Discord token
     * @returns {Promise<Object>} Decoded user information
     */
    async decodeToken(token) {
        // Check cache first
        const cacheKey = `token_${token}`;
        const cached = this.cache.get(cacheKey);
        if (cached && Date.now() - cached.timestamp < this.cacheTimeout) {
            return cached.data;
        }

        try {
            // Clean and validate token
            if (!token || typeof token !== 'string') {
                throw new Error('Invalid token provided');
            }

            // Clean token - remove any whitespace and common URL encoding issues
            const cleanToken = token.trim().replace(/\s+/g, '');

            console.log(`🔍 Attempting to decode token: ${cleanToken.substring(0, 20)}...`);

            // Use POST endpoint to avoid URL encoding issues
            const response = await fetch('/api/decode-token', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: JSON.stringify({ token: cleanToken })
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();

            // Cache the result only if successful
            if (data.valid) {
                this.cache.set(cacheKey, {
                    data: data,
                    timestamp: Date.now()
                });
            }

            console.log('✅ Token decode result:', data);
            return data;

        } catch (error) {
            console.error('❌ Failed to decode token:', error);
            return {
                status: 'error',
                message: 'Failed to decode token: ' + error.message,
                valid: false
            };
        }
    }

    /**
     * Get Discord info from URL parameters (token or direct parameters)
     * @returns {Promise<Object>} Discord user information
     */
    async getDiscordInfoFromURL() {
        const urlParams = new URLSearchParams(window.location.search);

        // Check for token first (preferred method)
        const token = urlParams.get('token');
        if (token) {
            console.log('🔍 Found token in URL, decoding...');
            const decoded = await this.decodeToken(token);

            if (decoded.valid) {
                return {
                    discord_id: decoded.discord_id,
                    discord_username: decoded.discord_username,
                    method: 'token',
                    expires_at: decoded.expires_at
                };
            } else {
                console.error('❌ Token decode failed:', decoded.message);
                return null;
            }
        }

        // Fallback to direct parameters (for backward compatibility)
        const discordId = urlParams.get('discord_id');
        const discordUsername = urlParams.get('discord_username');

        if (discordId && discordUsername) {
            console.log('⚠️ Using direct parameters (consider upgrading to tokens)');
            return {
                discord_id: discordId,
                discord_username: discordUsername,
                method: 'direct',
                expires_at: null
            };
        }

        // No Discord info found
        console.log('ℹ️ No Discord information found in URL');
        return null;
    }

    /**
     * Update form fields with Discord information
     * @param {Object} discordInfo - Discord user information
     */
    updateFormWithDiscordInfo(discordInfo) {
        if (!discordInfo) return;

        // Update Discord ID field
        const discordIdField = document.getElementById('discord_id');
        if (discordIdField) {
            discordIdField.value = discordInfo.discord_id;
            discordIdField.readOnly = true;
            discordIdField.style.backgroundColor = '#f5f5f5';
        }

        // Update Discord username field
        const discordUsernameField = document.getElementById('discord_username');
        if (discordUsernameField) {
            discordUsernameField.value = discordInfo.discord_username;
            discordUsernameField.readOnly = true;
            discordUsernameField.style.backgroundColor = '#f5f5f5';
        }

        // Show user-friendly message
        this.showDiscordInfoMessage(discordInfo);

        // Log for debugging
        console.log('✅ Form updated with Discord info:', discordInfo);
    }

    /**
     * Show Discord information to user
     * @param {Object} discordInfo - Discord user information
     */
    showDiscordInfoMessage(discordInfo) {
        // Create or update info display
        let infoDiv = document.getElementById('discord-info-display');
        if (!infoDiv) {
            infoDiv = document.createElement('div');
            infoDiv.id = 'discord-info-display';
            infoDiv.style.cssText = `
                background: #e8f4f8;
                border: 1px solid #b8daff;
                border-radius: 8px;
                padding: 15px;
                margin: 15px 0;
                text-align: center;
            `;

            // Insert before the form
            const form = document.getElementById('verification-form');
            if (form) {
                form.parentNode.insertBefore(infoDiv, form);
            } else {
                document.body.appendChild(infoDiv);
            }
        }

        // Update content
        infoDiv.innerHTML = `
            <div style="display: flex; align-items: center; justify-content: center; gap: 10px;">
                <span style="font-size: 24px;">👤</span>
                <div>
                    <strong>Discord Account Identified</strong><br>
                    <span style="color: #666;">${discordInfo.discord_username}</span>
                    ${discordInfo.expires_at ? `<br><small style="color: #999;">Session expires: ${new Date(discordInfo.expires_at).toLocaleString()}</small>` : ''}
                </div>
            </div>
        `;
    }

    /**
     * Handle token expiry
     * @param {Object} discordInfo - Discord user information
     */
    handleTokenExpiry(discordInfo) {
        if (!discordInfo || !discordInfo.expires_at) return;

        const expiresAt = new Date(discordInfo.expires_at);
        const now = new Date();
        const timeUntilExpiry = expiresAt - now;

        if (timeUntilExpiry <= 0) {
            // Token already expired
            this.showExpiredTokenMessage();
            return;
        }

        // Set warning for 5 minutes before expiry
        const warningTime = 5 * 60 * 1000; // 5 minutes
        if (timeUntilExpiry <= warningTime) {
            setTimeout(() => {
                this.showExpiringSoonMessage(expiresAt);
            }, timeUntilExpiry - warningTime);
        }

        // Set expiry handler
        setTimeout(() => {
            this.showExpiredTokenMessage();
        }, timeUntilExpiry);
    }

    /**
     * Show expired token message
     */
    showExpiredTokenMessage() {
        const message = `
            <div style="background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 8px; padding: 15px; margin: 15px 0; text-align: center;">
                <strong>⚠️ Session Expired</strong><br>
                Your Discord authentication session has expired. Please authenticate again.
                <br><br>
                <a href="/verify.html" style="background: #007bff; color: white; padding: 8px 16px; text-decoration: none; border-radius: 4px; display: inline-block; margin-top: 8px;">
                    Re-authenticate
                </a>
            </div>
        `;

        this.insertMessage(message);

        // Disable form
        const form = document.getElementById('verification-form');
        if (form) {
            form.style.opacity = '0.5';
            form.style.pointerEvents = 'none';
        }
    }

    /**
     * Show expiring soon message
     * @param {Date} expiresAt - Expiry time
     */
    showExpiringSoonMessage(expiresAt) {
        const message = `
            <div style="background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 8px; padding: 10px; margin: 10px 0; text-align: center;">
                <strong>⏰ Session Expiring Soon</strong><br>
                <small>Your session will expire at ${expiresAt.toLocaleString()}</small>
            </div>
        `;

        this.insertMessage(message);
    }

    /**
     * Insert message into page
     * @param {string} message - HTML message to insert
     */
    insertMessage(message) {
        // Remove existing messages
        const existing = document.getElementById('token-message');
        if (existing) {
            existing.remove();
        }

        // Create message container
        const messageDiv = document.createElement('div');
        messageDiv.id = 'token-message';
        messageDiv.innerHTML = message;

        // Insert at the top of the page
        const container = document.querySelector('.container, body');
        if (container) {
            container.insertBefore(messageDiv, container.firstChild);
        }
    }

    /**
     * Initialize token handler on page load
     */
    async initialize() {
        console.log('🚀 Initializing Token Handler...');

        try {
            // Get Discord info from URL
            const discordInfo = await this.getDiscordInfoFromURL();

            if (discordInfo) {
                console.log('✅ Discord info found:', discordInfo);

                // Update form with Discord information
                this.updateFormWithDiscordInfo(discordInfo);

                // Handle token expiry
                this.handleTokenExpiry(discordInfo);

                // Check if user is already verified
                if (window.verificationChecker) {
                    await window.verificationChecker.checkAndUpdateUI(discordInfo.discord_id, {
                        statusElement: document.getElementById('verification-status'),
                        buttonElement: document.getElementById('verify-button')
                    });
                }

            } else {
                console.log('ℹ️ No Discord authentication found');
                // Show authentication prompt
                this.showAuthenticationPrompt();
            }

        } catch (error) {
            console.error('❌ Token handler initialization failed:', error);
            this.showErrorMessage('Failed to load authentication information. Please try again.');
        }
    }

    /**
     * Show authentication prompt
     */
    showAuthenticationPrompt() {
        const message = `
            <div style="background: #e8f4f8; border: 1px solid #b8daff; border-radius: 8px; padding: 20px; margin: 20px 0; text-align: center;">
                <h3 style="margin-top: 0;">🔐 Discord Authentication Required</h3>
                <p>Please authenticate with Discord to continue with verification.</p>
                <a href="/verify.html" style="background: #7289da; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block; margin-top: 10px;">
                    Authenticate with Discord
                </a>
            </div>
        `;

        this.insertMessage(message);
    }

    /**
     * Show error message
     * @param {string} message - Error message
     */
    showErrorMessage(message) {
        const errorDiv = `
            <div style="background: #f8d7da; border: 1px solid #f5c6cb; border-radius: 8px; padding: 15px; margin: 15px 0; text-align: center;">
                <strong>❌ Error</strong><br>
                ${message}
            </div>
        `;

        this.insertMessage(errorDiv);
    }

    /**
     * Clear token cache
     */
    clearCache() {
        this.cache.clear();
        console.log('🗑️ Token cache cleared');
    }
}

// Global instance
window.tokenHandler = new TokenHandler();

// Auto-initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => window.tokenHandler.initialize());
} else {
    window.tokenHandler.initialize();
}

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = TokenHandler;
}