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

    // For now, just return success with the code for testing
    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      },
      body: JSON.stringify({
        success: true,
        code: code,
        message: 'Discord callback received successfully'
      })
    };

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