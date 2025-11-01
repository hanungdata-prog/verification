# Import the main FastAPI app from the app module
from app.main import app

# This allows Vercel to use the complete application with all endpoints
__all__ = ["app"]