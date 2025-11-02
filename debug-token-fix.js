/**
 * Debug script for token system fixes
 * Run this in browser console to test token generation/decoding
 */

async function debugTokenSystem() {
    console.log('🧪 Starting Token System Debug');
    console.log('================================');

    try {
        // 1. Test token generation
        console.log('\n📝 1. Testing Token Generation...');
        const testResponse = await fetch('/test-token');
        const testData = await testResponse.json();

        if (testData.status === 'success') {
            console.log('✅ Token generation successful');
            console.log('🔑 Token:', testData.token);
            console.log('🔗 Test URL:', testData.test_url);

            // 2. Test token decoding
            console.log('\n🔍 2. Testing Token Decoding...');
            const decodeResponse = await fetch('/api/decode-token', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: testData.token })
            });
            const decodeData = await decodeResponse.json();

            console.log('📊 Decode Result:', decodeData);

            if (decodeData.valid) {
                console.log('✅ Token decoding successful');
                console.log('👤 Discord ID:', decodeData.discord_id);
                console.log('👤 Discord Username:', decodeData.discord_username);
            } else {
                console.log('❌ Token decoding failed');
            }

            // 3. Test frontend token handler
            console.log('\n🖥️ 3. Testing Frontend Token Handler...');
            if (window.tokenHandler) {
                const frontendResult = await window.tokenHandler.decodeToken(testData.token);
                console.log('📱 Frontend Result:', frontendResult);

                if (frontendResult.valid) {
                    console.log('✅ Frontend token handler working');
                } else {
                    console.log('❌ Frontend token handler failed');
                }
            } else {
                console.log('❌ Token handler not available');
            }

            // 4. Test URL with token
            console.log('\n🌐 4. Testing URL Navigation...');
            console.log('🔗 Test URL:', testData.test_url);
            console.log('💡 Open this URL in a new tab to test the full flow');

        } else {
            console.log('❌ Token generation failed');
            console.log('Error:', testData.message);
        }

    } catch (error) {
        console.error('❌ Debug script failed:', error);
    }

    console.log('\n🏁 Debug Complete');
}

async function testCurrentURL() {
    console.log('🔍 Testing Current URL...');
    console.log('📋 Current URL:', window.location.href);

    if (window.tokenHandler) {
        try {
            const discordInfo = await window.tokenHandler.getDiscordInfoFromURL();
            console.log('👤 Discord Info from URL:', discordInfo);

            if (discordInfo) {
                console.log('✅ Successfully extracted Discord info from current URL');
            } else {
                console.log('❌ No Discord info found in current URL');
            }
        } catch (error) {
            console.error('❌ Error extracting Discord info:', error);
        }
    } else {
        console.log('❌ Token handler not available');
    }
}

// Run debugging functions
debugTokenSystem();
testCurrentURL();

// Make functions available globally
window.debugTokenSystem = debugTokenSystem;
window.testCurrentURL = testCurrentURL;

console.log('🔧 Debug functions loaded. Use debugTokenSystem() and testCurrentURL() to test.');