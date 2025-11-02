import hashlib
import hmac
import secrets
import re
import time
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
import json
import logging
import ipaddress
from urllib.parse import urlparse

import httpx
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
try:
    import redis.asyncio as redis
except ImportError:
    redis = None

logger = logging.getLogger(__name__)

class SecurityConfig:
    """Configuration for security settings"""
    ALLOWED_DOMAINS = [
        "authgateway.vercel.app",
        "localhost:3000",
        "localhost:8000",
        "127.0.0.1:3000",
        "127.0.0.1:8000"
    ]

    VPN_DETECTION_APIS = [
        "https://ipapi.co/{ip}/vpn/",
        "https://vpnapi.io/api/{ip}",
        "https://ipqualityscore.com/api/json/ip/{ip}?key={key}"
    ]

    SUSPICIOUS_USER_AGENTS = [
        r'.*bot.*',
        r'.*crawler.*',
        r'.*scraper.*',
        r'.*curl.*',
        r'.*wget.*',
        r'.*python.*',
        r'.*java.*',
        r'.*go-http.*'
    ]

    RATE_LIMITS = {
        "verify": "10/minute",
        "discord_callback": "5/minute",
        "admin": "100/hour"
    }

    BLOCKED_COUNTRIES = []  # Add country codes to block
    ALLOWED_COUNTRIES = []  # Empty means all countries allowed

    MAX_REQUESTS_PER_SESSION = 100
    SESSION_TIMEOUT = 3600  # 1 hour

class VPN_Detector:
    """Detect VPN/proxy usage using ProxyCheck.io and other APIs"""

    def __init__(self):
        self.cache = {}
        self.api_keys = {
            "ipqualityscore": os.getenv("IPQUALITYSCORE_API_KEY")
        }

    async def detect_vpn(self, ip: str) -> Tuple[bool, Dict]:
        """Detect if IP is using VPN/proxy using ProxyCheck.io"""
        # Check cache first
        if ip in self.cache:
            cache_time, result = self.cache[ip]
            if time.time() - cache_time < 3600:  # Cache for 1 hour
                return result

        detection_results = {
            "is_vpn": False,
            "is_proxy": False,
            "is_datacenter": False,
            "is_tor": False,
            "country": "unknown",
            "provider": "unknown",
            "confidence": 0.0,
            "api_used": "proxycheck.io"
        }

        try:
            # Primary method: ProxyCheck.io (free tier, 1000 requests/day)
            logger.info(f"🔍 Checking VPN status for {ip} using ProxyCheck.io")
            async with httpx.AsyncClient(timeout=15) as client:
                response = await client.get(f"https://proxycheck.io/v2/{ip}")

                if response.status_code == 200:
                    data = response.json()
                    logger.info(f"📋 ProxyCheck.io response for {ip}: {data}")

                    # Extract VPN/proxy information
                    proxy_info = data.get("proxy", "no")
                    is_proxy = proxy_info == "yes"

                    if is_proxy:
                        detection_results["is_vpn"] = True
                        detection_results["is_proxy"] = True
                        detection_results["confidence"] = 0.9

                    # Get additional info
                    detection_results["country"] = data.get("country", "unknown")
                    detection_results["provider"] = data.get("provider", "unknown")

                    # Check if datacenter IP
                    if data.get("type") == "datacenter":
                        detection_results["is_datacenter"] = True
                        detection_results["confidence"] = max(detection_results["confidence"], 0.7)

                    logger.info(f"✅ VPN detection complete for {ip}: is_vpn={detection_results['is_vpn']}")
                else:
                    logger.warning(f"⚠️ ProxyCheck.io API error for {ip}: {response.status_code}")

        except Exception as e:
            logger.warning(f"⚠️ ProxyCheck.io detection failed for {ip}: {e}")

            # Fallback to IP-API
            try:
                logger.info(f"🔄 Fallback: Using IP-API for {ip}")
                async with httpx.AsyncClient(timeout=10) as client:
                    response = await client.get(f"http://ip-api.com/json/{ip}")
                    if response.status_code == 200:
                        data = response.json()
                        if data.get("proxy") or data.get("hosting"):
                            detection_results["is_proxy"] = True
                            detection_results["is_datacenter"] = True
                            detection_results["confidence"] = 0.6
                        detection_results["country"] = data.get("countryCode", "unknown")
                        detection_results["provider"] = data.get("isp", "unknown")
                        detection_results["api_used"] = "ip-api"

            except Exception as e:
                logger.warning(f"⚠️ IP-API fallback failed for {ip}: {e}")

        # Final determination
        detection_results["is_vpn"] = (
            detection_results["is_proxy"] or
            detection_results["is_datacenter"] or
            detection_results["is_tor"]
        )

        # Cache result
        self.cache[ip] = (time.time(), detection_results["is_vpn"])

        logger.info(f"🎯 Final VPN detection for {ip}: {detection_results}")
        return detection_results["is_vpn"], detection_results

class DomainValidator:
    """Validate allowed domains"""

    def __init__(self, allowed_domains: List[str]):
        self.allowed_domains = [d.lower() for d in allowed_domains]

    def is_domain_allowed(self, request: Request) -> bool:
        """Check if the request domain is allowed"""
        try:
            origin = request.headers.get("origin")
            referer = request.headers.get("referer")
            host = request.headers.get("host")

            # Check Host header first
            if host:
                host_domain = host.split(":")[0].lower()
                if any(host_domain == allowed.split(":")[0] for allowed in self.allowed_domains):
                    return True

            # Check Origin header
            if origin:
                origin_domain = urlparse(origin).netloc.lower()
                if any(origin_domain == allowed for allowed in self.allowed_domains):
                    return True

            # Check Referer header
            if referer:
                referer_domain = urlparse(referer).netloc.lower()
                if any(referer_domain == allowed for allowed in self.allowed_domains):
                    return True

            return False
        except Exception as e:
            logger.error(f"Domain validation error: {e}")
            return False

class CSRFProtection:
    """CSRF protection using nonces"""

    def __init__(self):
        self.nonces = {}

    def generate_nonce(self, session_id: str) -> str:
        """Generate a new nonce for CSRF protection"""
        nonce = secrets.token_urlsafe(32)
        expiry = time.time() + 3600  # 1 hour expiry
        self.nonces[session_id] = (nonce, expiry)
        return nonce

    def validate_nonce(self, session_id: str, nonce: str) -> bool:
        """Validate a nonce"""
        if session_id not in self.nonces:
            return False

        stored_nonce, expiry = self.nonces[session_id]
        if time.time() > expiry:
            del self.nonces[session_id]
            return False

        return hmac.compare_digest(stored_nonce, nonce)

    def cleanup_expired(self):
        """Clean up expired nonces"""
        current_time = time.time()
        expired_sessions = [
            session_id for session_id, (_, expiry) in self.nonces.items()
            if current_time > expiry
        ]
        for session_id in expired_sessions:
            del self.nonces[session_id]

class SecurityMiddleware:
    """Main security middleware"""

    def __init__(self, config: SecurityConfig):
        self.config = config
        self.vpn_detector = VPN_Detector()
        self.domain_validator = DomainValidator(config.ALLOWED_DOMAINS)
        self.csrf_protection = CSRFProtection()
        self.blocked_ips: Set[str] = set()
        self.suspicious_activities: Dict[str, List] = {}
        self.redis_client = None

        # Initialize Redis if available
        try:
            import os
            redis_url = os.getenv("REDIS_URL")
            if redis_url:
                self.redis_client = redis.from_url(redis_url)
        except Exception as e:
            logger.warning(f"Redis not available: {e}")

    async def validate_request(self, request: Request) -> Dict:
        """Validate incoming request and return security context"""
        security_context = {
            "ip": self._get_client_ip(request),
            "user_agent": request.headers.get("user-agent", ""),
            "origin": request.headers.get("origin", ""),
            "referer": request.headers.get("referer", ""),
            "host": request.headers.get("host", ""),
            "session_id": self._get_session_id(request),
            "timestamp": datetime.utcnow(),
            "request": request
        }

        # Perform security checks
        await self._check_domain(security_context)
        await self._check_vpn(security_context)
        await self._check_user_agent(security_context)
        await self._check_rate_limit(security_context)
        await self._check_suspicious_patterns(security_context)

        return security_context

    async def _check_domain(self, context: Dict):
        """Check if domain is allowed"""
        if not self.domain_validator.is_domain_allowed(context["request"]):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Domain not allowed"
            )

    async def _check_vpn(self, context: Dict):
        """Check for VPN/proxy usage"""
        is_vpn, vpn_info = await self.vpn_detector.detect_vpn(context["ip"])

        if is_vpn:
            logger.warning(f"VPN detected from {context['ip']}: {vpn_info}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="VPN/Proxy usage is not allowed"
            )

    async def _check_user_agent(self, context: Dict):
        """Check for suspicious user agents"""
        user_agent = context["user_agent"].lower()

        for pattern in self.config.SUSPICIOUS_USER_AGENTS:
            if re.match(pattern, user_agent, re.IGNORECASE):
                logger.warning(f"Suspicious user agent detected: {user_agent}")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied: suspicious user agent"
                )

    async def _check_rate_limit(self, context: Dict):
        """Check rate limiting"""
        if self.redis_client:
            key = f"rate_limit:{context['ip']}:{context['session_id']}"
            current = await self.redis_client.incr(key)

            if current == 1:
                await self.redis_client.expire(key, 60)  # 1 minute

            if current > self.config.MAX_REQUESTS_PER_SESSION:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Rate limit exceeded"
                )

    async def _check_suspicious_patterns(self, context: Dict):
        """Check for suspicious activity patterns"""
        ip = context["ip"]

        # Track suspicious activities
        if ip not in self.suspicious_activities:
            self.suspicious_activities[ip] = []

        self.suspicious_activities[ip].append(context["timestamp"])

        # Clean old activities (older than 1 hour)
        cutoff_time = datetime.utcnow() - timedelta(hours=1)
        self.suspicious_activities[ip] = [
            activity for activity in self.suspicious_activities[ip]
            if activity > cutoff_time
        ]

        # Check for rapid succession requests
        if len(self.suspicious_activities[ip]) > 50:  # More than 50 requests in 1 hour
            logger.warning(f"Suspicious activity from {ip}: {len(self.suspicious_activities[ip])} requests/hour")

            if len(self.suspicious_activities[ip]) > 100:  # Block if > 100 requests/hour
                self.blocked_ips.add(ip)
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Blocked due to suspicious activity"
                )

    def _get_client_ip(self, request: Request) -> str:
        """Get client IP from request"""
        # Check various headers for real IP
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip

        return request.client.host if request.client else "unknown"

    def _get_session_id(self, request: Request) -> str:
        """Get or create session ID"""
        session_id = request.cookies.get("session_id")
        if not session_id:
            session_id = secrets.token_urlsafe(16)
        return session_id

    def generate_security_headers(self) -> Dict[str, str]:
        """Generate security headers"""
        return {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' https://apis.google.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self' https://discord.com https://cdn.discordapp.com;",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
        }

# Global security instance
security_config = SecurityConfig()
security_middleware = SecurityMiddleware(security_config)

async def validate_request_security(request: Request) -> Dict:
    """FastAPI dependency for security validation"""
    return await security_middleware.validate_request(request)

def get_security_headers() -> Dict[str, str]:
    """Get security headers for responses"""
    return security_middleware.generate_security_headers()

def generate_csrf_nonce(session_id: str) -> str:
    """Generate CSRF nonce"""
    return security_middleware.csrf_protection.generate_nonce(session_id)

def validate_csrf_nonce(session_id: str, nonce: str) -> bool:
    """Validate CSRF nonce"""
    return security_middleware.csrf_protection.validate_nonce(session_id, nonce)