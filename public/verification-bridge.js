/**
 * Verification Bridge - Check existing verification before allowing new verification
 * Prevents duplicate verifications and blocks already verified users
 */

class VerificationBridge {
    constructor() {
        this.checkInProgress = false;
        this.lastCheckTime = null;
        this.checkCooldown = 5000; // 5 seconds cooldown between checks
        this.cache = new Map();
        this.cacheTimeout = 30 * 1000; // 30 seconds cache timeout
    }

    /**
     * Check if user is already verified before allowing verification
     * @param {string} discordId - Discord user ID
     * @param {Object} options - Configuration options
     * @returns {Promise<Object>} Verification check result
     */
    async checkExistingVerification(discordId, options = {}) {
        const {
            blockIfVerified = true,
            showMessage = true,
            updateUI = true
        } = options;

        if (!discordId) {
            return {
                verified: false,
                message: "Discord ID is required",
                action: 'stop'
            };
        }

        // Check cache first
        const cacheKey = `verification_${discordId}`;
        const cached = this.cache.get(cacheKey);
        if (cached && Date.now() - cached.timestamp < this.cacheTimeout) {
            if (cached.verified) {
                if (updateUI) {
                    this.handleAlreadyVerified(cached.data, showMessage);
                }
                return {
                    verified: true,
                    cached: true,
                    message: "User already verified (cached)",
                    action: blockIfVerified ? 'block' : 'allow',
                    data: cached.data
                };
            }
        }

        // Implement cooldown to prevent too many checks
        if (this.checkInProgress) {
            return {
                verified: false,
                message: "Verification check in progress",
                action: 'wait'
            };
        }

        if (this.lastCheckTime && Date.now() - this.lastCheckTime < this.checkCooldown) {
            return {
                verified: false,
                message: "Please wait before checking again",
                action: 'wait'
            };
        }

        this.checkInProgress = true;
        this.lastCheckTime = Date.now();

        try {
            console.log(`🔍 Checking existing verification for Discord ID: ${discordId}`);

            // Call backend to check verification status
            const response = await fetch('/api/check-user-verification', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: JSON.stringify({ discord_id: discordId })
            });

            const data = await response.json();

            if (response.ok && data.status === 'success') {
                const isVerified = data.is_verified;
                const verificationData = data.verification_data || {};

                // Cache the result
                this.cache.set(cacheKey, {
                    verified: isVerified,
                    data: verificationData,
                    timestamp: Date.now()
                });

                if (isVerified) {
                    console.log(`❌ User ${discordId} already verified at ${verificationData.time_ago}`);

                    if (updateUI) {
                        this.handleAlreadyVerified(verificationData, showMessage);
                    }

                    return {
                        verified: true,
                        message: `User already verified ${verificationData.time_ago}`,
                        action: blockIfVerified ? 'block' : 'allow',
                        data: verificationData
                    };
                } else {
                    console.log(`✅ User ${discordId} not verified, verification allowed`);
                    return {
                        verified: false,
                        message: "User not verified, verification allowed",
                        action: 'allow'
                    };
                }
            } else {
                console.error(`❌ Verification check failed: ${data.message}`);
                return {
                    verified: false,
                    message: `Verification check failed: ${data.message}`,
                    action: 'allow', // Allow verification if check fails
                    error: true
                };
            }

        } catch (error) {
            console.error('❌ Error checking existing verification:', error);
            return {
                verified: false,
                message: 'Failed to check verification status',
                action: 'allow', // Allow verification if check fails
                error: true
            };
        } finally {
            this.checkInProgress = false;
        }
    }

    /**
     * Handle already verified users
     * @param {Object} verificationData - Verification data
     * @param {boolean} showMessage - Whether to show message
     */
    handleAlreadyVerified(verificationData, showMessage = true) {
        // Show error message to user
        if (showMessage) {
            const timeAgo = verificationData.time_ago || 'previously';
            const discordUsername = verificationData.discord_username || 'Unknown User';
            const verificationDate = verificationData.verification_date || '';
            const method = verificationData.method || 'unknown';

            const message = `
                <div style="background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 8px; padding: 20px; margin: 20px 0; text-align: center;">
                    <h3 style="color: #856404; margin: 0 0 10px 0;">⚠️ Already Verified</h3>
                    <p style="margin: 0 0 15px 0; color: #856404;">
                        <strong>${discordUsername}</strong> has already been verified <strong>${timeAgo}</strong>.
                    </p>
                    ${verificationDate ? `<p style="margin: 0; color: #856404; font-size: 0.9em;">
                        Verification date: ${new Date(verificationDate).toLocaleString()}
                    </p>` : ''}
                    ${method ? `<p style="margin: 0; color: #856404; font-size: 0.9em;">
                        Verification method: ${method}
                    </p>` : ''}
                    <p style="margin: 15px 0 0 0; color: #6c757d; font-size: 0.9em;">
                        Each Discord account can only be verified once.
                    </p>
                </div>
            `;

            this.showMessage(message, 'warning');
        }

        // Disable verification button
        const verifyButton = document.getElementById('verify-button');
        if (verifyButton) {
            verifyButton.disabled = true;
            verifyButton.textContent = 'Already Verified';
            verifyButton.style.opacity = '0.5';
            verifyButton.style.cursor = 'not-allowed';
        }

        // Disable form inputs
        const form = document.getElementById('verification-form');
        if (form) {
            const inputs = form.querySelectorAll('input, button, select, textarea');
            inputs.forEach(input => {
                if (input.id !== 'discordId' && input.id !== 'discordUsername') {
                    input.disabled = true;
                    input.style.opacity = '0.5';
                }
            });
        }
    }

    /**
     * Show message to user
     * @param {string} message - Message to show
     * @param {string} type - Message type (success, error, warning, info)
     */
    showMessage(message, type = 'info') {
        // Remove existing messages
        const existingMessages = document.querySelectorAll('.verification-message');
        existingMessages.forEach(msg => msg.remove());

        // Create message container
        const messageContainer = document.createElement('div');
        messageContainer.className = 'verification-message';
        messageContainer.innerHTML = message;

        // Add styles based on type
        const styles = {
            success: {
                background: '#d4edda',
                border: '1px solid #c3e6cb',
                color: '#155724'
            },
            error: {
                background: '#f8d7da',
                border: '1px solid #f5c6cb',
                color: '#721c24'
            },
            warning: {
                background: '#fff3cd',
                border: '1px solid #ffeaa7',
                color: '#856404'
            },
            info: {
                background: '#d1ecf1',
                border: '1px solid #bee5eb',
                color: '#0c5460'
            }
        };

        const style = styles[type] || styles.info;
        Object.assign(messageContainer.style, {
            ...style,
            padding: '15px',
            'border-radius': '8px',
            'margin': '15px 0',
            'font-family': 'Arial, sans-serif',
            'font-size': '14px',
            'line-height': '1.4'
        });

        // Insert message at the top of the content
        const container = document.querySelector('.container, body');
        if (container) {
            container.insertBefore(messageContainer, container.firstChild);
        }
    }

    /**
     * Clear verification cache
     * @param {string} discordId - Optional Discord ID to clear specific cache
     */
    clearCache(discordId = null) {
        if (discordId) {
            this.cache.delete(`verification_${discordId}`);
            console.log(`🗑️ Cleared cache for Discord ID: ${discordId}`);
        } else {
            this.cache.clear();
            console.log('🗑️ Cleared all verification cache');
        }
    }

    /**
     * Get verification status from cache
     * @param {string} discordId - Discord user ID
     * @returns {Object|null} Cached verification data
     */
    getCachedVerification(discordId) {
        const cacheKey = `verification_${discordId}`;
        const cached = this.cache.get(cacheKey);

        if (cached && Date.now() - cached.timestamp < this.cacheTimeout) {
            return cached;
        }

        return null;
    }

    /**
     * Check verification with UI integration
     * @param {string} discordId - Discord user ID
     * @returns {Promise<boolean>} True if verification should proceed, false if blocked
     */
    async checkVerificationWithUI(discordId) {
        const result = await this.checkExistingVerification(discordId, {
            blockIfVerified: true,
            showMessage: true,
            updateUI: true
        });

        return result.action === 'allow';
    }

    /**
     * Initialize verification bridge
     */
    initialize() {
        console.log('🔗 Verification Bridge initialized');
    }
}

// Global instance
window.verificationBridge = new VerificationBridge();

// Auto-initialize
document.addEventListener('DOMContentLoaded', () => {
    window.verificationBridge.initialize();
});

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = VerificationBridge;
}