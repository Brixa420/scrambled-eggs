#!/bin/bash

# Activate virtual environment (if using one)
# source venv/bin/activate  # On Windows: .\venv\Scripts\activate

# Set environment variables
export SECRET_KEY="your-secret-key-here"
export ALGORITHM="HS256"
export ACCESS_TOKEN_EXPIRE_MINUTES=1440  # 24 hours

# Run the FastAPI application
uvicorn app.main:app --reload
