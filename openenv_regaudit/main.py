#!/usr/bin/env python3
"""
Main entry point for running RegAudit OpenEnv locally.
"""

import uvicorn
from api.server import app

if __name__ == "__main__":
    uvicorn.run(
        "api.server:app",
        host="127.0.0.1",
        port=7860,
        reload=True
    )