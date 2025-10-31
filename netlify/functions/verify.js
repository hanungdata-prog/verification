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
    console.log('HCAPTCHA_SECRET_KEY exists:', !!process.env.HCAPTCHA_SECRET_KEY);

    // Temporarily skip hCaptcha validation for testing if secret key is not set
    if (!process.env.HCAPTCHA_SECRET_KEY) {
      console.log('WARNING: HCAPTCHA_SECRET_KEY not set, skipping CAPTCHA validation for testing');
    } else {
      let captchaValid;
      try {
        captchaValid = await validateHcaptcha(captcha_token, event.headers['x-forwarded-for'] || event.requestContext.identity.sourceIp);
        console.log('CAPTCHA validation result:', captchaValid);

        if (!captchaValid) {
          return {
            statusCode: 400,
            headers: {
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': '*'
            },
            body: JSON.stringify({
              error: 'CAPTCHA validation failed'
            })
          };
        }
      } catch (captchaError) {
        console.error('CAPTCHA validation error:', captchaError);
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
    const response = await fetch('https://hcaptcha.com/siteverify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: `response=${token}&secret=${process.env.HCAPTCHA_SECRET_KEY}&remoteip=${ip}`
    });

    const result = await response.json();
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