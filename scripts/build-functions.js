#!/usr/bin/env node

const fs = require('fs-extra');
const path = require('path');
const chalk = require('chalk');

const log = {
  info: (msg) => console.log(chalk.blue('ℹ'), msg),
  success: (msg) => console.log(chalk.green('✅'), msg),
  error: (msg) => console.log(chalk.red('❌'), msg),
  warn: (msg) => console.log(chalk.yellow('⚠'), msg)
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

    // Copy other necessary files
    const otherFiles = ['.env.example', 'verifications.json'];
    for (const file of otherFiles) {
      if (await fs.pathExists(file)) {
        await fs.copy(file, `netlify/functions/${file}`);
        log.success(`Copied ${file} to netlify/functions/`);
      }
    }

    // Create main serverless function
    const mainFunction = `#!/usr/bin/env python3
"""
Netlify serverless function for AuthGateway
"""
import sys
import os
from pathlib import Path

# Add the app directory to Python path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

# Set environment variables for serverless
os.environ.setdefault('PYTHONPATH', str(current_dir))
os.environ.setdefault('PYTHONUNBUFFERED', '1')

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
    Netlify Functions handler
    """
    try:
        # Parse the event for AWS Lambda format
        from mangum import Mangum
        mangum_handler = Mangum(app)
        return mangum_handler(event, context)
    except ImportError:
        # Fallback without mangum
        import json
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                "message": "AuthGateway is running",
                "status": "serverless fallback mode",
                "note": "Install mangum for full functionality"
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