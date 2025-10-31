# AuthGateway - Discord Verification Service

Exotic Roleplay Gateway is a modern Discord verification service built with FastAPI and designed for deployment on modern platforms like Vercel and Netlify.

## 🚀 Quick Start

### Prerequisites
- Python 3.9+
- Node.js 16+
- npm or yarn

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd AuthGateway
   ```

2. **Setup the project**
   ```bash
   npm run setup
   ```

3. **Configure environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Start development server**
   ```bash
   npm run dev
   ```

## 📋 Available Scripts

```bash
# Development
npm run dev              # Start development server with hot reload
npm run dev:uvicorn      # Start with uvicorn directly

# Building & Deployment
npm run build            # Build for serverless deployment
npm run start            # Start production server
npm run start:production # Start with production settings

# Maintenance
npm run setup            # Initial project setup
npm run lint             # Code linting
npm run lint:fix         # Auto-fix linting issues
npm run test             # Run tests

# Platform-specific builds
npm run vercel-build      # Build for Vercel
npm run netlify-build     # Build for Netlify
```

## 🚀 Modern Deployment

This application is ready for production deployment with built-in security features and optimized performance.

## Overview

This service presents a simple web form where users complete a CAPTCHA challenge and submit their Discord ID. On the backend, this information is validated, encrypted, stored in a PostgreSQL database, and - on successful verification - a webhook fires to your Discord channel, assigning roles or sending alerts.

## Features

- Static verification form with CAPTCHA integration (Google reCAPTCHA or hCaptcha)
- FastAPI backend with IP encryption using Fernet (AES-128)
- PostgreSQL database storage with SQLModel
- Discord webhook integration with HMAC signature verification
- Rate limiting (5 attempts per 10 minutes per IP)
- Admin verification listing endpoint
- Privacy policy page
- Docker containerization with docker-compose

## Setup Instructions

### Prerequisites

- Python 3.11+
- Docker and Docker Compose (for containerization)
- PostgreSQL (if not using Docker)

### Local Setup

1. Clone the repository:

```bash
git clone <repository-url>
cd exotic-roleplay-gateway
```

2. Install Python dependencies:

```bash
pip install -r requirements.txt
```

3. Create a `.env` file from the example:

```bash
cp .env.example .env
```

4. Edit the `.env` file with your configuration:

```env
# Database Configuration
DATABASE_URL=postgresql://username:password@localhost:5432/verifications

# Encryption Configuration - Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
FERNET_KEY=your_fernet_key_here

# CAPTCHA Configuration
CAPTCHA_PROVIDER=recaptcha  # Options: recaptcha, hcaptcha
CAPTCHA_SECRET=your_captcha_secret_key

# Discord Webhook Configuration
DISCORD_WEBHOOK_URL=your_discord_webhook_url
WEBHOOK_SECRET=your_webhook_secret

# Admin Credentials
ADMIN_USERNAME=your_admin_username
ADMIN_PASSWORD=your_admin_password
```

5. Run the application:

```bash
python -m app.main
```

The application will be available at `http://localhost:8000`

### Docker Setup

1. Build and run with Docker Compose:

```bash
docker-compose up --build
```

The application will be available at `http://localhost:8000`

## Environment Variables

- `DATABASE_URL`: Database connection string (PostgreSQL or SQLite)
- `FERNET_KEY`: Encryption key for IP address encryption
- `CAPTCHA_PROVIDER`: Either 'recaptcha' or 'hcaptcha'
- `CAPTCHA_SECRET`: Secret key for CAPTCHA validation
- `DISCORD_WEBHOOK_URL`: Discord webhook URL for notifications (contains the secret token in the URL)
- `ADMIN_USERNAME`: Username for admin endpoint authentication
- `ADMIN_PASSWORD`: Password for admin endpoint authentication
- `ALLOWED_ORIGINS`: Comma-separated list of allowed origins for CORS (default: *)

## API Endpoints

- `GET /` - Serves the verification form
- `POST /verify` - Main verification endpoint
- `GET /admin/verifications` - Admin endpoint to list verifications (requires auth)
- `GET /privacy` - Privacy policy page

## Example Discord.js Webhook Listener

```javascript
const express = require('express');
const app = express();

app.use(express.json());

// Handle verification webhooks from your service
app.post('/webhook', (req, res) => {
  // Note: Discord webhooks don't require HMAC signatures 
  // as the security is handled by the secret token in the webhook URL
  const { success, discord_id, discord_username, timestamp, method } = req.body;
  
  if (success) {
    console.log(`Verification successful for ${discord_username} (${discord_id})`);
    // Add user to verified role, send welcome message, etc.
  } else {
    console.log(`Verification failed for ${discord_username} (${discord_id})`);
    // Log failed attempt, take other actions as needed
  }
  
  res.status(200).send('Webhook received');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Webhook listener running on port ${PORT}`);
});
```

## Privacy and Legal Notes

- This service encrypts IP addresses before storing them to protect user privacy
- Only successful verifications are stored in the database
- User data is only used for verification purposes
- The service implements GDPR-compliant data handling
- Admin endpoint requires authentication to access verification records

## Security Best Practices

- Always use HTTPS in production
- Rotate your FERNET_KEY regularly
- Keep your CAPTCHA secrets secure
- Use strong credentials for the admin endpoint
- Monitor logs for suspicious activity

## 🚀 Deployment

### Prerequisites

- Python 3.8+
- pip package manager
- Virtual environment (recommended)

### Quick Deployment

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd exotic-roleplay-gateway
   ```

2. **Create a virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables:**
   ```bash
   cp .env.production .env
   # Edit .env with your actual values
   ```

5. **Run the application:**
   ```bash
   python run_server.py
   ```

### Docker Deployment

1. **Build the Docker image:**
   ```bash
   docker build -t auth-gateway .
   ```

2. **Run the container:**
   ```bash
   docker run -p 8000:8000 --env-file .env auth-gateway
   ```

### Docker Compose Deployment

```bash
docker-compose up --build
```

### Environment Variables

Create a `.env` file with the following variables:

```
# Database Configuration
DATABASE_URL=postgresql://username:password@localhost:5432/verifications

# Encryption Configuration - Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
FERNET_KEY=your_fernet_key_here

# CAPTCHA Configuration
CAPTCHA_PROVIDER=hcaptcha
CAPTCHA_SECRET=your_captcha_secret_key

# Discord Webhook Configuration
DISCORD_WEBHOOK_URL=your_discord_webhook_url

# Admin Credentials
ADMIN_USERNAME=your_admin_username
ADMIN_PASSWORD=your_admin_password

# CORS Configuration
BASE_URL=https://yourdomain.com
ALLOWED_ORIGINS=["https://yourdomain.com"]
```

## 🛡️ Security Features

- Rate limiting to prevent abuse
- Encrypted IP address storage
- Secure Discord OAuth2 integration
- CSRF protection
- XSS protection
- SQL injection prevention
- Secure headers
- Input validation and sanitization

## 📊 Monitoring

- Structured JSON logging
- Health check endpoints
- Performance metrics
- Error tracking and reporting

## 🔄 Backup and Recovery

- Automatic data backup
- Point-in-time recovery
- Disaster recovery procedures
- Data retention policies

## 📈 Scaling

- Horizontal scaling support
- Load balancing configuration
- Database connection pooling
- Caching strategies

## License

MIT License - See LICENSE file for details.