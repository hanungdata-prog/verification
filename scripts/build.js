#!/usr/bin/env node

const fs = require('fs-extra');
const path = require('path');
const chalk = require('chalk');

const log = {
};

async function build() {
  try {
    log.info('Starting build process...');

    // Create necessary directories
    await fs.ensureDir('api');
    await fs.ensureDir('public');
    await fs.ensureDir('dist');

    // Copy Python app files to api directory for serverless deployment
    log.info('Preparing Python files for deployment...');

    // Copy app directory
    if (await fs.pathExists('app')) {
      await fs.copy('app', 'api/app');
      log.success('Copied app directory to api/');
    }

    // Copy static files to public directory
    if (await fs.pathExists('static')) {
      await fs.copy('static', 'public');
      log.success('Copied static files to public/');
    }

    // Copy root Python files
    const rootFiles = [
      'requirements.txt',
      '.env.example',
      'verifications.json'
    ];

    for (const file of rootFiles) {
      if (await fs.pathExists(file)) {
        await fs.copy(file, `api/${file}`);
        log.success(`Copied ${file} to api/`);
      }
    }

    // Create Vercel serverless function entry point
    const apiIndex = `#!/usr/bin/env python3
import sys
import os
from pathlib import Path

# Add the app directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

# Import the FastAPI app
from app.main import app

# Vercel entry point
handler = app

# Export for Vercel
def handler_vercel(request):
    return app(request.scope, request.receive, request.send)
`;

    await fs.writeFile('api/index.py', apiIndex);
    log.success('Created Vercel serverless entry point');

    // Create vercel.json if not exists
    const vercelConfig = {
      "version": 2,
      "builds": [
        {
          "src": "api/index.py",
          "use": "@vercel/python"
        }
      ],
      "routes": [
        {
          "src": "/api/(.*)",
          "dest": "/api/index.py"
        },
        {
          "src": "/(.*)",
          "dest": "/public/$1"
        }
      ],
      "functions": {
        "api/index.py": {
          "runtime": "python3.9"
        }
      },
      "env": {
        "PYTHONPATH": "$PYTHONPATH:/var/task"
      }
    };

    await fs.writeJSON('vercel.json', vercelConfig, { spaces: 2 });
    log.success('Created vercel.json configuration');

    log.success('Build completed successfully!');
    log.info('Project is ready for deployment to Vercel or Netlify');

  } catch (error) {
    log.error('Build failed:', error.message);
    process.exit(1);
  }
}

if (require.main === module) {
  build();
}

module.exports = { build };