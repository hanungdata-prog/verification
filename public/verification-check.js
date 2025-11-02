/**
 * Verification Status Checker
 * Prevents double verification by checking if user is already verified
 */

class VerificationChecker {
    constructor() {
        this.apiBaseUrl = '';
        this.isChecking = false;
        this.cache = new Map();
        this.cacheTimeout = 5 * 60 * 1000; // 5 minutes cache
    }

    /**
     * Check if a Discord user is already verified
     * @param {string} discordId - Discord user ID
     * @returns {Promise<Object>} Verification status
     */
    async checkVerificationStatus(discordId) {
        // Check cache first
        const cacheKey = `verify_${discordId}`;
        const cached = this.cache.get(cacheKey);
        if (cached && Date.now() - cached.timestamp < this.cacheTimeout) {
            return cached.data;
        }

        if (this.isChecking) {
            throw new Error('Verification check already in progress');
        }

        this.isChecking = true;

        try {
            const response = await fetch(`/api/check-verification/${discordId}`, {
                method: 'GET',
                headers: {
                    'Accept': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                }
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();

            // Cache the result
            this.cache.set(cacheKey, {
                data: data,
                timestamp: Date.now()
            });

            console.log('Verification status check result:', data);
            return data;

        } catch (error) {
            console.error('Failed to check verification status:', error);
            throw error;
        } finally {
            this.isChecking = false;
        }
    }

    /**
     * Check verification status via POST (more secure)
     * @param {string} discordId - Discord user ID
     * @returns {Promise<Object>} Verification status
     */
    async checkVerificationStatusPost(discordId) {
        if (this.isChecking) {
            throw new Error('Verification check already in progress');
        }

        this.isChecking = true;

        try {
            const response = await fetch('/api/check-user-verification', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: JSON.stringify({ discord_id: discordId })
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();

            // Cache the result
            const cacheKey = `verify_${discordId}`;
            this.cache.set(cacheKey, {
                data: data,
                timestamp: Date.now()
            });

            console.log('Verification status check result:', data);
            return data;

        } catch (error) {
            console.error('Failed to check verification status:', error);
            throw error;
        } finally {
            this.isChecking = false;
        }
    }

    /**
     * Check verification status and handle UI updates
     * @param {string} discordId - Discord user ID
     * @param {Object} options - UI options
     */
    async checkAndUpdateUI(discordId, options = {}) {
        const {
            loadingElement = null,
            statusElement = null,
            buttonElement = null,
            onAlreadyVerified = null,
            onNotVerified = null,
            onError = null
        } = options;

        try {
            // Show loading state
            if (loadingElement) {
                loadingElement.style.display = 'block';
                loadingElement.textContent = 'Checking verification status...';
            }

            if (buttonElement) {
                buttonElement.disabled = true;
                buttonElement.textContent = 'Checking...';
            }

            // Check verification status
            const result = await this.checkVerificationStatusPost(discordId);

            // Hide loading state
            if (loadingElement) {
                loadingElement.style.display = 'none';
            }

            if (result.is_verified) {
                // User is already verified
                if (statusElement) {
                    statusElement.innerHTML = `
                        <div style="color: #28a745; padding: 10px; border-radius: 5px; background: #d4edda; margin: 10px 0;">
                            <strong>✅ Already Verified</strong><br>
                            <small>Verified ${result.verification_data.time_ago}</small><br>
                            <small>Username: ${result.verification_data.discord_username}</small>
                        </div>
                    `;
                }

                if (buttonElement) {
                    buttonElement.disabled = true;
                    buttonElement.textContent = 'Already Verified';
                    buttonElement.style.opacity = '0.5';
                }

                // Show error message
                this.showAlreadyVerifiedMessage(result.verification_data);

                // Call callback
                if (onAlreadyVerified) {
                    onAlreadyVerified(result);
                }

                return { verified: true, data: result };
            } else {
                // User is not verified yet
                if (statusElement) {
                    statusElement.innerHTML = `
                        <div style="color: #007bff; padding: 10px; border-radius: 5px; background: #d1ecf1; margin: 10px 0;">
                            <strong>ℹ️ Ready to Verify</strong><br>
                            <small>This account has not been verified yet</small>
                        </div>
                    `;
                }

                if (buttonElement) {
                    buttonElement.disabled = false;
                    buttonElement.textContent = 'Verify Account';
                }

                // Call callback
                if (onNotVerified) {
                    onNotVerified(result);
                }

                return { verified: false, data: result };
            }

        } catch (error) {
            console.error('Verification check failed:', error);

            // Hide loading state
            if (loadingElement) {
                loadingElement.style.display = 'none';
            }

            if (statusElement) {
                statusElement.innerHTML = `
                    <div style="color: #dc3545; padding: 10px; border-radius: 5px; background: #f8d7da; margin: 10px 0;">
                        <strong>❌ Error</strong><br>
                        <small>Failed to check verification status: ${error.message}</small>
                    </div>
                `;
            }

            if (buttonElement) {
                buttonElement.disabled = false;
                buttonElement.textContent = 'Retry Check';
            }

            // Call error callback
            if (onError) {
                onError(error);
            }

            return { verified: null, error: error };
        }
    }

    /**
     * Show "already verified" message to user
     * @param {Object} verificationData - Verification details
     */
    showAlreadyVerifiedMessage(verificationData) {
        // Create modal or show alert
        const message = `
            This Discord account has already been verified!

            Details:
            • Username: ${verificationData.discord_username}
            • Verified: ${verificationData.time_ago}
            • Method: ${verificationData.method}

            Each Discord account can only be verified once.
        `;

        // Show in modal if available, otherwise alert
        if (window.showModal) {
            window.showModal('Already Verified', message);
        } else {
            alert(message);
        }

        // Also redirect to error page after a delay
        setTimeout(() => {
            window.location.href = `/security-error.html?reason=already_verified&message=This Discord account has already been verified ${verificationData.time_ago}. Each Discord account can only be verified once.`;
        }, 3000);
    }

    /**
     * Clear cache
     * @param {string} discordId - Optional specific Discord ID to clear
     */
    clearCache(discordId = null) {
        if (discordId) {
            this.cache.delete(`verify_${discordId}`);
        } else {
            this.cache.clear();
        }
    }

    /**
     * Get verification statistics
     * @returns {Promise<Object>} Verification stats
     */
    async getVerificationStats() {
        try {
            const response = await fetch('/api/verification-stats', {
                method: 'GET',
                headers: {
                    'Accept': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                }
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            return await response.json();
        } catch (error) {
            console.error('Failed to get verification stats:', error);
            throw error;
        }
    }
}

// Global instance
window.verificationChecker = new VerificationChecker();

// Auto-setup for common scenarios
document.addEventListener('DOMContentLoaded', () => {
    // If there's a Discord ID in URL (from OAuth callback), check verification status
    const urlParams = new URLSearchParams(window.location.search);
    const discordId = urlParams.get('discord_id');

    if (discordId && window.location.pathname.includes('verify-auto')) {
        console.log('Auto-checking verification status for Discord ID:', discordId);

        // Check verification status
        window.verificationChecker.checkAndUpdateUI(discordId, {
            statusElement: document.getElementById('verification-status'),
            buttonElement: document.getElementById('verify-button'),
            onAlreadyVerified: (result) => {
                console.log('User already verified:', result);
            },
            onNotVerified: (result) => {
                console.log('User ready to verify:', result);
                // Auto-enable verification form
                const form = document.getElementById('verification-form');
                if (form) {
                    form.style.display = 'block';
                }
            },
            onError: (error) => {
                console.error('Verification check failed:', error);
            }
        });
    }
});

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = VerificationChecker;
}