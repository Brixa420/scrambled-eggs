"""
Start the model serving server.
"""
import sys
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from brixa.ai.serving.server import ModelServer
from brixa.ai.registry.registry import ModelRegistry

def main():
    # Initialize model registry
    registry = ModelRegistry()
    
    # Register our sentiment model
    model_path = project_root / "models" / "sentiment_model.pt"
    if not model_path.exists():
        print("Error: Model not found. Please train the model first using train_sentiment.py")
        return
    
    model_id = "sentiment-analysis"
    version = "1.0.0"
    
    # Register the model
    registry.register_model(
        model_id=model_id,
        version=version,
        model_path=str(model_path),
        framework="pytorch",
        input_type="tensor",
        output_type="tensor",
        description="Simple sentiment analysis model"
    )
    
    # Start the server
    server = ModelServer(registry=registry, host="0.0.0.0", port=8000)
    print("Starting model server on http://localhost:8000")
    print("API Documentation: http://localhost:8000/docs")
    server.run()

if __name__ == "__main__":
    main()
