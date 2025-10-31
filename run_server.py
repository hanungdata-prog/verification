import uvicorn
import sys
from app.main import app

if __name__ == "__main__":
    # Try different ports if 8000 is occupied
    ports_to_try = [8000, 8001, 8002, 8080]
    
    for port in ports_to_try:
        try:
            print(f"Attempting to start server on port {port}...")
            uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")
            break
        except OSError as e:
            if "Address already in use" in str(e) or "[WinError 10048]" in str(e):
                print(f"Port {port} is already in use, trying next port...")
                continue
            else:
                print(f"Error starting server: {e}")
                sys.exit(1)
        except Exception as e:
            print(f"Unexpected error: {e}")
            sys.exit(1)
    else:
        print("Could not start server on any of the attempted ports.")
        sys.exit(1)