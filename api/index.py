"""
Vercel Serverless Function Entrypoint for FORESIGHT.
Discovers and exports the FastAPI ASGI application instance.
"""

import sys
import os

# Ensure repository root is in Python module search path
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

# Set serverless environment indicator
os.environ.setdefault("VERCEL", "1")

# Export FastAPI app for Vercel's @vercel/python runtime
from backend.main import app
