"""
Train and save a simple sentiment analysis model.
"""
import os
import sys
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from brixa.ai.examples.sentiment_model import train_model, save_model

def main():
    print("Training sentiment analysis model...")
    model = train_model(epochs=5)
    
    # Create models directory if it doesn't exist
    models_dir = project_root / "models"
    models_dir.mkdir(exist_ok=True)
    
    # Save the model
    model_path = models_dir / "sentiment_model.pt"
    save_model(model, model_path)
    print(f"Model saved to {model_path}")

if __name__ == "__main__":
    main()
