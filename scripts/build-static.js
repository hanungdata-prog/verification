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

async function buildStatic() {
  try {
    log.info('Building static files...');

    // Create dist directory for static build output
    await fs.ensureDir('dist');

    // Copy public files to dist
    if (await fs.pathExists('public')) {
      await fs.copy('public', 'dist');
      log.success('Copied public files to dist/');
    }

    // Create an index.html if it doesn't exist
    const indexPath = path.join('dist', 'index.html');
    if (!await fs.pathExists(indexPath)) {
      const indexContent = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AuthGateway - Discord Verification Service</title>
    <meta name="description" content="Secure Discord verification service for Exotic Roleplay">
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            background: white;
            border-radius: 12px;
            padding: 40px;
            text-align: center;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            max-width: 500px;
        }
        h1 {
            color: #333;
            margin-bottom: 20px;
        }
        .btn {
            display: inline-block;
            background: #667eea;
            color: white;
            padding: 12px 30px;
            text-decoration: none;
            border-radius: 6px;
            margin: 10px;
            transition: background 0.3s;
        }
        .btn:hover {
            background: #5a6fd8;
        }
        .status {
            margin: 20px 0;
            padding: 15px;
            background: #e8f5e8;
            border-radius: 6px;
            color: #2d5a2d;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 AuthGateway</h1>
        <p>Exotic Roleplay Discord Verification Service</p>

        <div class="status">
            ✅ Service is running
            <br>API endpoints available at /api/*
        </div>

        <a href="/verify.html" class="btn">Verify Account</a>
        <a href="/verify-auto.html" class="btn">Auto Verify</a>
        <a href="/admin/verifications" class="btn">Admin Panel</a>

        <p style="margin-top: 30px; font-size: 14px; color: #666;">
            Need help? Contact our support team
        </p>
    </div>

    <script>
        // Check if API is available
        fetch('/api/health')
            .then(() => console.log('API is available'))
            .catch(() => console.log('API not available - using static mode'));
    </script>
</body>
</html>`;

      await fs.writeFile(indexPath, indexContent);
      log.success('Created index.html');
    }

    // Copy _redirects file to root of dist
    const redirectsSrc = path.join('public', '_redirects');
    const redirectsDest = path.join('dist', '_redirects');
    if (await fs.pathExists(redirectsSrc)) {
      await fs.copy(redirectsSrc, redirectsDest);
      log.success('Copied _redirects file to dist/');
    }

    log.success('Static build completed successfully!');
    log.info('Static files ready in dist/ directory');

  } catch (error) {
    log.error('Static build failed:', error.message);
    process.exit(1);
  }
}

if (require.main === module) {
  buildStatic();
}

module.exports = { buildStatic };