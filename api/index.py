# Import the main FastAPI app from the app module
try:
    from app.main import app
    print("Successfully imported FastAPI app from app.main")
except Exception as e:
    print(f"Error importing from app.main: {e}")
    # Fallback to a minimal app if import fails
    from fastapi import FastAPI
    app = FastAPI()

    @app.get("/")
    async def root():
        return {"message": "AuthGateway is running in fallback mode", "status": "serverless"}

# This allows Vercel to use the complete application with all endpoints
__all__ = ["app"]