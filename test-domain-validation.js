/**
 * Test script to verify domain validation is working correctly
 */

// Test domain validation in browser console
function testDomainValidation() {
    console.log('🧪 Testing Domain Validation');
    console.log('================================');

    // Simulate different domains
    const testDomains = [
        'apinode1a2b3c4d5e6f7g8h9i0j1k2l3m4n.vercel.app',  // Your current domain
        'authgateway.vercel.app',                           // Original domain
        'localhost',                                        // Local development
        'localhost:3000',                                   // Local with port
        '127.0.0.1',                                        // Local IP
        'malicious-site.com',                               // Should be blocked
        'evil.vercel.app'                                   // Should be allowed by pattern
    ];

    // Get the domain validation function from security.js
    const currentDomain = window.location.hostname;
    console.log(`📋 Current domain: ${currentDomain}`);

    // Create a test security manager instance
    const testSecurityManager = {
        allowedPatterns: [
            /\.vercel\.app$/,  // All *.vercel.app subdomains
            /^localhost/,     // localhost and localhost:*
            /^127\.0\.0\.1/,  // 127.0.0.1 and 127.0.0.1:*
            /^192\.168\./,    // Local network IPs
            /^10\./,          // Private network IPs
            /^172\.(1[6-9]|2[0-9]|3[0-1])\./  // Private network IPs
        ],
        explicitDomains: [
            'authgateway.vercel.app',
            'localhost',
            '127.0.0.1'
        ],

        testDomain: function(domain) {
            // Check explicit domains first
            const isExplicitlyAllowed = this.explicitDomains.some(allowed => {
                return domain === allowed || domain.endsWith(`.${allowed}`);
            });

            // Then check patterns
            const isPatternAllowed = this.allowedPatterns.some(pattern => {
                return pattern.test(domain);
            });

            const isAllowed = isExplicitlyAllowed || isPatternAllowed;

            console.log(`🔍 ${domain}: ${isAllowed ? '✅ ALLOWED' : '❌ BLOCKED'}`);
            if (isAllowed) {
                if (isExplicitlyAllowed) {
                    console.log(`   Reason: Explicitly allowed`);
                } else {
                    console.log(`   Reason: Pattern matched`);
                }
            }

            return isAllowed;
        }
    };

    // Test all domains
    testDomains.forEach(domain => {
        testSecurityManager.testDomain(domain);
    });

    console.log('\n📋 Summary:');
    console.log('✅ All vercel.app subdomains should be allowed');
    console.log('✅ Local development domains should be allowed');
    console.log('⚠️ Unknown domains will log warnings but should still work');
}

// Test the current security manager if available
function testCurrentSecurityManager() {
    console.log('\n🧪 Testing Current Security Manager');
    console.log('===================================');

    if (window.securityManager) {
        const currentDomain = window.location.hostname;
        console.log(`📋 Current domain: ${currentDomain}`);

        // Test domain validation
        try {
            window.securityManager.validateDomain();
            console.log('✅ Domain validation passed');

            // Check security status
            const status = window.securityManager.getSecurityStatus();
            console.log('📊 Security status:', status);

        } catch (error) {
            console.error('❌ Domain validation failed:', error);
        }
    } else {
        console.log('❌ SecurityManager not found - make sure security.js is loaded');
    }
}

// Run tests
console.log('🚀 Domain Validation Tests');
console.log('========================');

testDomainValidation();
testCurrentSecurityManager();

console.log('\n💡 If tests pass, your domain validation issue should be resolved!');
console.log('🔄 Refresh the page to see if the "Invalid Domain Access" error is gone.');