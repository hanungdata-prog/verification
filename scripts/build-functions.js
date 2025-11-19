#!/usr/bin/env node

const fs = require('fs-extra');
const path = require('path');
const chalk = require('chalk');

const log = {
  info: (message, ...args) => {
    console.log(chalk.blue('ℹ'), message, ...args);
  },
  success: (message, ...args) => {
    console.log(chalk.green('✓'), message, ...args);
  },
  error: (message, ...args) => {
    console.error(chalk.red('✗'), message, ...args);
  },
  warn: (message, ...args) => {
    console.warn(chalk.yellow('⚠'), message, ...args);
  }
};

async function buildFunctions() {
  try {
    log.info('Building serverless functions...');

    // Create netlify/functions directory
    await fs.ensureDir('netlify/functions');

    // Copy app files to netlify/functions
    if (await fs.pathExists('app')) {
      await fs.copy('app', 'netlify/functions/app');
      log.success('Copied app files to netlify/functions/');
    }

    // Copy requirements files
    const requirementsFiles = ['requirements.txt', 'requirements-serverless.txt'];
    for (const file of requirementsFiles) {
      if (await fs.pathExists(file)) {
        await fs.copy(file, `netlify/functions/${file}`);
        log.success(`Copied ${file} to netlify/functions/`);
      }
    }

    // Copy other necessary files (skip .env.example to avoid exposing secrets)
    const otherFiles = ['verifications.json'];
    for (const file of otherFiles) {
      if (await fs.pathExists(file)) {
        await fs.copy(file, `netlify/functions/${file}`);
        log.success(`Copied ${file} to netlify/functions/`);
      }
    }

    // Note: Static files are served by Vercel, not by FastAPI

    // Create main serverless function with improved routing
    const mainFunction = `#!/usr/bin/env python3
"""
Netlify serverless function for AuthGateway
"""
import sys
import os
import json
from pathlib import Path

# Add the app directory to Python path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

# Set environment variables for serverless
os.environ.setdefault('PYTHONPATH', str(current_dir))
os.environ.setdefault('PYTHONUNBUFFERED', '1')

# Set BASE_URL for deployment
if not os.getenv('BASE_URL'):
    # Try to detect the base URL from the environment or use a default
    deployment_url = os.getenv('URL') or os.getenv('VERCEL_URL') or os.getenv('NETLIFY_URL') or 'https://apinode1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2-a64eej8it.vercel.app'
    if deployment_url and not deployment_url.startswith('http'):
        deployment_url = f"https://{deployment_url}"
    os.environ.setdefault('BASE_URL', deployment_url)
    print(f"🌐 Setting BASE_URL to: {deployment_url}")

# Set Discord redirect URI if not already set
if not os.getenv('DISCORD_REDIRECT_URI'):
    base_url = os.getenv('BASE_URL', 'https://apinode1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2-a64eej8it.vercel.app')
    discord_redirect_uri = f"{base_url}/discord/callback"
    os.environ.setdefault('DISCORD_REDIRECT_URI', discord_redirect_uri)
    print(f"🔗 Setting DISCORD_REDIRECT_URI to: {discord_redirect_uri}")

# Import the FastAPI app
try:
    from app.main import app
    print("✅ FastAPI app imported successfully")
except ImportError as e:
    print(f"❌ Failed to import FastAPI app: {e}")

    # Create fallback app
    from fastapi import FastAPI
    app = FastAPI(title="AuthGateway")

    @app.get("/")
    async def root():
        return {"message": "AuthGateway is running", "status": "serverless mode"}

# AWS Lambda / Netlify Functions handler
def handler(event, context):
    """
    Netlify Functions handler with path routing support
    """
    try:
        # Import mangum for FastAPI adapter
        from mangum import Mangum

        # Extract path from event
        path = event.get('path', '/')
        http_method = event.get('httpMethod', 'GET')

        # Check for path override in query parameters (for Discord OAuth routes)
        query_params = event.get('queryStringParameters') or {}
        override_path = query_params.get('path')

        if override_path:
            path = override_path
            print(f"🔄 Path overridden to: {path}")

        # Handle routing for Discord OAuth and other paths
        if path.startswith('/discord/'):
            # Discord OAuth routes
            print(f"🔗 Discord OAuth route: {http_method} {path}")
        elif path.startswith('/api/'):
            # API routes
            print(f"🔌 API route: {http_method} {path}")
        elif path.startswith('/verify') or path.startswith('/admin'):
            # Verification and admin routes
            print(f"✅ Verification route: {http_method} {path}")
        else:
            # Root and other routes
            print(f"🏠 Root route: {http_method} {path}")

        # Use Mangum to handle FastAPI app
        mangum_handler = Mangum(app)
        return mangum_handler(event, context)

    except ImportError:
        # Fallback without mangum
        print("⚠️ Mangum not available, using fallback mode")
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                "message": "AuthGateway is running",
                "status": "serverless fallback mode",
                "note": "Install mangum for full functionality",
                "path": event.get('path', '/'),
                "method": event.get('httpMethod', 'GET')
            })
        }
    except Exception as e:
        # Error handling
        print(f"❌ Error in handler: {e}")
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                "error": "Internal server error",
                "message": str(e),
                "path": event.get('path', '/')
            })
        }

# Export for Netlify
lambda_handler = handler

# Local testing
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
`;

    await fs.writeFile('netlify/functions/api.py', mainFunction);
    log.success('Created main serverless function');

    log.success('Serverless functions build completed!');
    log.info('Functions ready in netlify/functions/ directory');

  } catch (error) {
    log.error('Functions build failed:', error.message);
    process.exit(1);
  }
}

if (require.main === module) {
  buildFunctions();
}

module.exports = { buildFunctions };