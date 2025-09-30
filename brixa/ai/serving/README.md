# Model Serving System

This module provides a FastAPI-based server for serving AI models with the following features:

- Model versioning and management
- Automatic model loading and caching
- REST API for predictions
- Health checks and metrics
- Swagger/OpenAPI documentation

## Quick Start

### 1. Train a Model

```bash
# Train a simple sentiment analysis model
python scripts/train_sentiment.py
```

### 2. Start the Server

```bash
python scripts/start_server.py
```

The server will start on `http://localhost:8000` with API documentation available at `http://localhost:8000/docs`.

### 3. Test the API

Run the test script to verify everything is working:

```bash
python -m pytest tests/test_model_serving.py -v
```

## API Endpoints

- `GET /health`: Check server health
- `GET /models`: List all available models
- `GET /models/{model_id}/{version}/info`: Get model info
- `POST /models/{model_id}/{version}/predict`: Make predictions

## Example Client

```python
import requests

# Make a prediction
response = requests.post(
    "http://localhost:8000/models/sentiment-analysis/1.0.0/predict",
    json={"input": [[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]]}  # Example input
)
print(response.json())
```

## Adding New Models

1. Implement your model following the same pattern as `sentiment_model.py`
2. Train and save your model using the provided utilities
3. Register the model with the `ModelRegistry` in `start_server.py`
4. The model will be automatically loaded when requested

## Configuration

Server configuration can be modified in `scripts/start_server.py`:

- Host and port
- Model loading settings
- Logging configuration
- Caching behavior
