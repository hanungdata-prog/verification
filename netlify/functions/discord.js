exports.handler = async (event, context) => {
  try {
    console.log('Discord callback function called');
    console.log('Event:', event);

    // Extract query parameters
    const code = event.queryStringParameters?.code;
    const error = event.queryStringParameters?.error;

    if (error) {
      return {
        statusCode: 400,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        },
        body: JSON.stringify({
          error: error,
          error_description: event.queryStringParameters?.error_description
        })
      };
    }

    if (!code) {
      return {
        statusCode: 400,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        },
        body: JSON.stringify({
          error: 'No authorization code provided'
        })
      };
    }

    // Exchange code for Discord user information and redirect to verify-auto page
    try {
      const https = require('https');
      const querystring = require('querystring');

      // Discord OAuth configuration
      const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
      const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
      const REDIRECT_URI = process.env.DISCORD_REDIRECT_URI || 'https://verification-gateway-joblow.netlify.app/discord/callback';

      if (!CLIENT_ID || !CLIENT_SECRET) {
        return {
          statusCode: 500,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
          },
          body: JSON.stringify({
            error: 'Discord credentials not configured'
          })
        };
      }

      // Exchange code for access token
      const tokenData = querystring.stringify({
        grant_type: 'authorization_code',
        code: code,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        redirect_uri: REDIRECT_URI,
      });

      // Exchange code for access token
      const tokenResponse = await new Promise((resolve, reject) => {
        const req = https.request('https://discord.com/api/oauth2/token', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': Buffer.byteLength(tokenData)
          }
        }, (res) => {
          let data = '';
          res.on('data', chunk => data += chunk);
          res.on('end', () => {
            try {
              resolve(JSON.parse(data));
            } catch (e) {
              reject(e);
            }
          });
        });

        req.on('error', reject);
        req.write(tokenData);
        req.end();
      });

      if (!tokenResponse.access_token) {
        return {
          statusCode: 400,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
          },
          body: JSON.stringify({
            error: 'Failed to get access token from Discord'
          })
        };
      }

      // Get user info
      const userResponse = await new Promise((resolve, reject) => {
        const req = https.request('https://discord.com/api/users/@me', {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${tokenResponse.access_token}`
          }
        }, (res) => {
          let data = '';
          res.on('data', chunk => data += chunk);
          res.on('end', () => {
            try {
              resolve(JSON.parse(data));
            } catch (e) {
              reject(e);
            }
          });
        });

        req.on('error', reject);
        req.end();
      });

      // Prepare user data
      const discordUser = {
        id: userResponse.id,
        username: userResponse.username,
        discriminator: userResponse.discriminator,
        avatar: userResponse.avatar,
        full_username: `${userResponse.username}#${userResponse.discriminator}`
      };

      // Return success with redirect to verify-auto page
      return {
        statusCode: 200,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        },
        body: JSON.stringify({
          success: true,
          redirect_url: `/verify-auto.html?discord_id=${discordUser.id}&discord_username=${encodeURIComponent(discordUser.full_username)}`,
          user: discordUser
        })
      };

    } catch (error) {
      console.error('Error exchanging Discord code:', error);
      return {
        statusCode: 500,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        },
        body: JSON.stringify({
          error: 'Failed to exchange Discord code',
          message: error.message
        })
      };
    }

  } catch (error) {
    console.error('Error in Discord callback:', error);
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