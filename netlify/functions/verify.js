const fetch = require('node-fetch');

exports.handler = async (event, context) => {
  try {
    console.log('=== VERIFICATION FUNCTION CALLED ===');
    console.log('HTTP Method:', event.httpMethod);
    console.log('Path:', event.path);
    console.log('Headers:', JSON.stringify(event.headers, null, 2));
    console.log('Body:', event.body);

    // Only allow POST requests
    if (event.httpMethod !== 'POST') {
      return {
        statusCode: 405,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        },
        body: JSON.stringify({
          error: 'Method not allowed'
        })
      };
    }

    // Parse the request body
    const requestBody = JSON.parse(event.body);
    console.log('Request body:', requestBody);

    const { discord_id, discord_username, captcha_token, metadata } = requestBody;

    console.log('Captcha token received:', captcha_token ? 'YES' : 'NO');
    console.log('Captcha token length:', captcha_token ? captcha_token.length : 0);
    console.log('Captcha token starts with:', captcha_token ? captcha_token.substring(0, 20) + '...' : 'NULL');

    // Validate required fields
    if (!discord_id || !discord_username || !captcha_token) {
      return {
        statusCode: 400,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        },
        body: JSON.stringify({
          error: 'Missing required fields: discord_id, discord_username, captcha_token'
        })
      };
    }

    // Validate CAPTCHA token (using hCaptcha)
    console.log('Validating hCaptcha token...');
    console.log('CAPTCHA_SECRET exists:', !!process.env.CAPTCHA_SECRET);
    console.log('CAPTCHA_SECRET value:', process.env.CAPTCHA_SECRET);

    // Skip hCaptcha validation if secret key is not set or is a placeholder value
    const isPlaceholderSecret = !process.env.CAPTCHA_SECRET || 
                               process.env.CAPTCHA_SECRET.includes('ES_67a2630d8c19468297fa9832fb8966c6') || 
                               process.env.CAPTCHA_SECRET.includes('ES_67a2630d8c19468297fa9832fb8966c6') ||
                               process.env.CAPTCHA_SECRET.trim() === '';
                               
    console.log('CAPTCHA_SECRET analysis:');
    console.log('- CAPTCHA_SECRET exists:', !!process.env.CAPTCHA_SECRET);
    console.log('- CAPTCHA_SECRET length:', process.env.CAPTCHA_SECRET ? process.env.CAPTCHA_SECRET.length : 0);
    console.log('- Is placeholder:', isPlaceholderSecret);
    console.log('- CAPTCHA_SECRET preview:', process.env.CAPTCHA_SECRET ? process.env.CAPTCHA_SECRET.substring(0, 10) + '...' : 'N/A');
    
    // Check if we have a standard hCaptcha token (starts with 0x and reasonable length)
    // Or a custom token (starts with P1_ or similar)
    const isStandardHcaptchaToken = captcha_token && 
                                   captcha_token.startsWith('0x') && 
                                   captcha_token.length > 20 && 
                                   captcha_token.length < 200;
                                   
    const isCustomToken = captcha_token && captcha_token.startsWith('P1_');

    console.log('Token analysis:');
    console.log('- Standard hCaptcha format:', isStandardHcaptchaToken);
    console.log('- Custom token format:', isCustomToken);
    console.log('- Token length:', captcha_token ? captcha_token.length : 0);
    console.log('- Token starts with:', captcha_token ? captcha_token.substring(0, 5) : 'N/A');

    if (isPlaceholderSecret) {
      console.log('WARNING: CAPTCHA_SECRET not properly configured, skipping CAPTCHA validation');
      console.log('Real CAPTCHA_SECRET should be set in environment variables');
    } else if (isCustomToken) {
      // If this is a custom token (P1_ format), we need to extract the actual hCaptcha token
      console.log('Processing custom token format - attempting to extract hCaptcha token');
      
      // The format appears to be P1_.[JWT_HEADER].[JWT_PAYLOAD].[JWT_SIGNATURE]
      // Let's try to decode the JWT payload to see if it contains the original hCaptcha token
      let extractedToken = captcha_token;
      let useCustom = true;
      
      if (captcha_token.startsWith('P1_')) {
        try {
          const tokenWithoutPrefix = captcha_token.substring(3); // Remove "P1_" prefix
          const parts = tokenWithoutPrefix.split('.');
          
          if (parts.length === 3) {
            // Decode the JWT payload (middle part) to check for hCaptcha token
            const payloadB64 = parts[1];
            // Add padding if necessary
            const padding = '='.repeat((4 - payloadB64.length % 4) % 4);
            const payloadPadded = payloadB64 + padding;
            const payloadDecoded = Buffer.from(payloadPadded, 'base64').toString('utf8');
            const payloadObj = JSON.parse(payloadDecoded);
            
            console.log('Decoded JWT payload:', payloadObj);
            
            // Check if the payload contains the original hCaptcha token
            // Common field names where it might be stored
            if (payloadObj.original_token || payloadObj.hcaptcha_token || payloadObj.token) {
              const originalHcaptchaToken = payloadObj.original_token || 
                                           payloadObj.hcaptcha_token || 
                                           payloadObj.token;
              
              console.log('Found potential hCaptcha token inside JWT:', originalHcaptchaToken.substring(0, 20) + '...');
              
              // Validate the original hCaptcha token instead
              let captchaValid = await validateHcaptcha(originalHcaptchaToken, event.headers['x-forwarded-for'] || event.requestContext.identity.sourceIp);
              console.log('Original hCaptcha token validation result:', captchaValid);
              
              if (!captchaValid) {
                return {
                  statusCode: 400,
                  headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                  },
                  body: JSON.stringify({
                    error: 'CAPTCHA validation failed',
                    details: 'Please ensure you complete the CAPTCHA verification correctly and try again.',
                    debug_info: {
                      captcha_token_received: !!captcha_token,
                      captcha_token_length: captcha_token ? captcha_token.length : 0,
                      captcha_token_format: isStandardHcaptchaToken ? 'standard' : isCustomToken ? 'custom' : 'unknown',
                      original_hcaptcha_token_found: !!originalHcaptchaToken,
                      original_hcaptcha_token_length: originalHcaptchaToken ? originalHcaptchaToken.length : 0,
                      original_token_format_valid: originalHcaptchaToken?.startsWith('0x') || false,
                      secret_key_configured: !!process.env.CAPTCHA_SECRET,
                      secret_key_length: process.env.CAPTCHA_SECRET ? process.env.CAPTCHA_SECRET.length : 0,
                      secret_key_is_placeholder: isPlaceholderSecret,
                      ip_address: event.headers['x-forwarded-for'] || event.requestContext.identity.sourceIp
                    }
                  })
                };
              } else {
                console.log('Original hCaptcha token validation successful');
              }
              useCustom = false; // We've already validated with the original token
            } else {
              console.log('No hCaptcha token found inside JWT payload');
            }
          }
        } catch (decodeError) {
          console.error('Error decoding custom token:', decodeError);
          // If decoding fails, proceed with the original custom token
        }
      }
      
      // If we didn't find and validate an original hCaptcha token inside the JWT,
      // try validating the custom token as-is (which will likely fail)
      if (useCustom) {
        let captchaValid = false;
        try {
          captchaValid = await validateHcaptcha(extractedToken, event.headers['x-forwarded-for'] || event.requestContext.identity.sourceIp);
          console.log('Custom token validation result:', captchaValid);
        } catch (captchaError) {
          console.error('Custom token validation error:', captchaError);
        }
        
        if (!captchaValid) {
          return {
            statusCode: 400,
            headers: {
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': '*'
            },
            body: JSON.stringify({
              error: 'CAPTCHA validation failed',
              details: 'Please ensure you complete the CAPTCHA verification correctly and try again. Custom token format detected.',
              debug_info: {
                captcha_token_received: !!captcha_token,
                captcha_token_length: captcha_token ? captcha_token.length : 0,
                captcha_token_format: isStandardHcaptchaToken ? 'standard' : isCustomToken ? 'custom' : 'unknown',
                secret_key_configured: !!process.env.CAPTCHA_SECRET,
                secret_key_length: process.env.CAPTCHA_SECRET ? process.env.CAPTCHA_SECRET.length : 0,
                secret_key_is_placeholder: isPlaceholderSecret,
                secret_key_preview: process.env.CAPTCHA_SECRET ? process.env.CAPTCHA_SECRET.substring(0, 15) + '...' : 'N/A',
                ip_address: event.headers['x-forwarded-for'] || event.requestContext.identity.sourceIp
              }
            })
          };
        } else {
          console.log('Custom token validation successful');
        }
      }
    } else {
      // Process as standard hCaptcha token
      let captchaValid;
      try {
        console.log('Starting standard CAPTCHA validation with token length:', captcha_token ? captcha_token.length : 0);
        captchaValid = await validateHcaptcha(captcha_token, event.headers['x-forwarded-for'] || event.requestContext.identity.sourceIp);
        console.log('Standard CAPTCHA validation result:', captchaValid);

        if (!captchaValid) {
          return {
            statusCode: 400,
            headers: {
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': '*'
            },
            body: JSON.stringify({
              error: 'CAPTCHA validation failed',
              details: 'Please ensure you complete the CAPTCHA verification correctly and try again.',
              debug_info: {
                captcha_token_received: !!captcha_token,
                captcha_token_length: captcha_token ? captcha_token.length : 0,
                captcha_token_format: isStandardHcaptchaToken ? 'standard' : isCustomToken ? 'custom' : 'unknown',
                secret_key_configured: !!process.env.CAPTCHA_SECRET,
                secret_key_length: process.env.CAPTCHA_SECRET ? process.env.CAPTCHA_SECRET.length : 0,
                secret_key_is_placeholder: isPlaceholderSecret,
                secret_key_preview: process.env.CAPTCHA_SECRET ? process.env.CAPTCHA_SECRET.substring(0, 15) + '...' : 'N/A',
                ip_address: event.headers['x-forwarded-for'] || event.requestContext.identity.sourceIp
              }
            })
          };
        } else {
          console.log('Standard CAPTCHA validation successful');
        }
      } catch (captchaError) {
        console.error('Standard CAPTCHA validation error:', captchaError);
        return {
          statusCode: 400,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
          },
          body: JSON.stringify({
            error: 'CAPTCHA validation failed',
            details: captchaError.message
          })
        };
      }
    }

    // Store verification in Supabase
    const verificationData = {
      verification_id: 'ver_' + Math.random().toString(36).substr(2, 16) + Date.now().toString(36),
      discord_id,
      discord_username,
      ip_address: event.headers['x-forwarded-for'] || event.requestContext.identity.sourceIp,
      user_agent: event.headers['user-agent'] || '',
      method: 'captcha',
      extra_data: metadata || {},
      verified_at: new Date().toISOString()
    };

    console.log('Storing verification data in Supabase...');
    console.log('SUPABASE_URL exists:', !!process.env.SUPABASE_URL);
    console.log('SUPABASE_KEY exists:', !!process.env.SUPABASE_KEY);

    const supabaseResult = await storeInSupabase(verificationData);
    console.log('Supabase result:', supabaseResult);

    if (supabaseResult.error) {
      console.error('Supabase error:', supabaseResult.error);
      return {
        statusCode: 500,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        },
        body: JSON.stringify({
          error: 'Failed to store verification data',
          details: supabaseResult.error
        })
      };
    }

    // Return success with redirect to Discord
    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      },
      body: JSON.stringify({
        success: true,
        message: 'Verification successful!',
        redirect_url: 'https://discord.gg/UNpRpJMt',
        verification_id: supabaseResult.data?.id
      })
    };

  } catch (error) {
    console.error('Error in verification function:', error);
    return {
      statusCode: 500,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      },
      body: JSON.stringify({
        error: 'Internal server error',
        message: error.message
      })
    };
  }
};

// Validate hCaptcha token
async function validateHcaptcha(token, ip) {
  try {
    console.log('Sending hCaptcha verification request...');
    console.log('Token length:', token ? token.length : 'null');
    console.log('IP:', ip);
    console.log('Secret configured:', !!process.env.CAPTCHA_SECRET);
    console.log('Secret starts with "0x":', process.env.CAPTCHA_SECRET && process.env.CAPTCHA_SECRET.startsWith('0x'));

    const response = await fetch('https://api.hcaptcha.com/siteverify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: `response=${encodeURIComponent(token)}&secret=${encodeURIComponent(process.env.CAPTCHA_SECRET)}&remoteip=${encodeURIComponent(ip || '')}`
    });

    console.log('hCaptcha API response status:', response.status);

    const result = await response.json();
    console.log('hCaptcha API response:', result);

    return result.success;
  } catch (error) {
    console.error('CAPTCHA validation error:', error);
    return false;
  }
}

// Store verification data in Supabase
async function storeInSupabase(data) {
  try {
    const SUPABASE_URL = process.env.SUPABASE_URL;
    const SUPABASE_KEY = process.env.SUPABASE_KEY;

    if (!SUPABASE_URL || !SUPABASE_KEY) {
      throw new Error('Supabase credentials not configured');
    }

    const response = await fetch(`${SUPABASE_URL}/rest/v1/verifications`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${SUPABASE_KEY}`,
        'apikey': SUPABASE_KEY,
        'Prefer': 'return=minimal'
      },
      body: JSON.stringify(data)
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Supabase error: ${response.status} - ${errorText}`);
    }

    // Get the ID of the inserted record
    const location = response.headers.get('location');
    if (location) {
      const id = location.split('/').pop();
      return { data: { id }, error: null };
    }

    return { data: null, error: null };
  } catch (error) {
    console.error('Supabase storage error:', error);
    return { data: null, error: error.message };
  }
}