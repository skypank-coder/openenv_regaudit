"""
HuggingFace Spaces entry point for RegAudit OpenEnv API.
Loads the FastAPI application from api/server.py and exposes it for Spaces deployment.
"""

from api.server import app

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=7860,
        reload=False
    )
