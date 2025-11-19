#!/usr/bin/env node

const fs = require('fs-extra');
const path = require('path');
const chalk = require('chalk');

const log = {
};

async function setup() {
  try {
    log.info('Setting up AuthGateway project...');

    // Check if Python is installed
    const { spawn } = require('child_process');

    await new Promise((resolve, reject) => {
      const python = spawn('python', ['--version']);
      python.on('close', (code) => {
        if (code === 0) {
          log.success('Python is available');
          resolve();
        } else {
          log.error('Python is not installed or not in PATH');
          reject(new Error('Python not found'));
        }
      });
    });

    // Create .env file if it doesn't exist
    if (!await fs.pathExists('.env')) {
      if (await fs.pathExists('.env.example')) {
        await fs.copy('.env.example', '.env');
        log.success('Created .env file from .env.example');
        log.warn('Please update .env with your actual configuration');
      } else {
        const defaultEnv = `# Discord Configuration
DISCORD_CLIENT_ID=your_discord_client_id
DISCORD_CLIENT_SECRET=your_discord_client_secret
DISCORD_REDIRECT_URI=http://localhost:8000/discord/callback
DISCORD_BOT_TOKEN=your_discord_bot_token

# CAPTCHA Configuration
RECAPTCHA_SECRET_KEY=your_recaptcha_secret_key
HCAPTCHA_SECRET_KEY=your_hcaptcha_secret_key

# Security
SECRET_KEY=your_secret_key_here
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your_admin_password

# Webhook
DISCORD_WEBHOOK_URL=your_discord_webhook_url

# Development
DEBUG=true
ENVIRONMENT=development
`;
        await fs.writeFile('.env', defaultEnv);
        log.success('Created default .env file');
      }
    }

    // Create logs directory
    await fs.ensureDir('logs');
    log.success('Created logs directory');

    // Create initial verifications.json if not exists
    if (!await fs.pathExists('verifications.json')) {
      await fs.writeJSON('verifications.json', []);
      log.success('Created verifications.json');
    }

    // Install npm dependencies
    log.info('Installing npm dependencies...');
    const { execSync } = require('child_process');
    try {
      execSync('npm install', { stdio: 'inherit' });
      log.success('npm dependencies installed');
    } catch (error) {
      log.warn('npm install failed, you may need to run it manually');
    }

    log.success('Setup completed successfully!');
    log.info('You can now run:');
    log.info('  npm run dev     - Start development server');
    log.info('  npm run build   - Build for deployment');
    log.info('  npm start       - Start production server');

  } catch (error) {
    log.error('Setup failed:', error.message);
    process.exit(1);
  }
}

if (require.main === module) {
  setup();
}

module.exports = { setup };