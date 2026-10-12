"""
FORESIGHT Startup Script
Run this script to launch the FORESIGHT server.
Usage: python run.py
"""

import sys
import uvicorn

if __name__ == "__main__":
    print("=" * 65)
    print(" FORESIGHT: QR Code Destination Analysis & Risk Assessment")
    print(" Tagline: 'Know the risk before you take the step.'")
    print(" Server starting on http://localhost:8000")
    print("=" * 65)
    # Bind to 0.0.0.0 so localhost and local IP both work
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=False)
