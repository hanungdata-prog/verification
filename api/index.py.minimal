from fastapi import FastAPI
from fastapi.responses import HTMLResponse

# Create simple FastAPI app
app = FastAPI()

@app.get("/")
async def root():
    return {"message": "AuthGateway is running", "status": "serverless"}

@app.get("/api/health")
async def health():
    return {"status": "healthy"}

@app.get("/discord/callback", response_class=HTMLResponse)
async def discord_callback(code: str = None, error: str = None):
    if error:
        return """
        <html>
        <body style="font-family: Arial; text-align: center; margin: 50px;">
            <h1 style="color: red;">❌ Authorization Failed</h1>
            <p>Discord authorization was cancelled or failed.</p>
            <a href="/verify.html" style="background: #7289DA; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Try Again</a>
        </body>
        </html>
        """

    if code:
        return """
        <html>
        <body style="font-family: Arial; text-align: center; margin: 50px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; color: white;">
            <div style="background: rgba(255,255,255,0.1); padding: 40px; border-radius: 12px; max-width: 600px; margin: 50px auto;">
                <h1 style="color: #4CAF50;">✅ Discord Authorization Successful!</h1>
                <h2>Verification Complete</h2>
                <p>Your Discord account has been verified successfully.</p>
                <p>You can now return to the Discord server.</p>
                <div style="margin: 30px 0;">
                    <a href="/" style="background: #4CAF50; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; margin: 10px;">Return Home</a>
                    <a href="/verify.html" style="background: #7289DA; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; margin: 10px;">Back to Verification</a>
                </div>
            </div>
            <script>
                setTimeout(() => { if(window.opener) window.close(); }, 5000);
            </script>
        </body>
        </html>
        """

    return """
    <html>
    <body style="font-family: Arial; text-align: center; margin: 50px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; color: white;">
        <div style="background: rgba(255,255,255,0.1); padding: 40px; border-radius: 12px; max-width: 500px; margin: 50px auto;">
            <h1>🔐 Discord Verification</h1>
            <p>Please complete the authorization process.</p>
            <a href="/verify.html" style="background: #7289DA; color: white; padding: 15px 30px; text-decoration: none; border-radius: 6px; display: inline-block;">Start Verification</a>
        </div>
    </body>
    </html>
    """

@app.get("/verify")
async def verify():
    return {"message": "Verification endpoint", "redirect_to": "/verify.html"}

@app.get("/admin")
async def admin():
    return {"message": "Admin endpoint", "status": "requires authentication"}

@app.get("/favicon.ico")
@app.get("/favicon.png")
async def favicon():
    return {"status": "no favicon"}