#!/usr/bin/env python3
"""
Script to train and register models in the model registry.
"""
import os
import sys
import logging
from pathlib import Path
from datetime import datetime

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

import torch
from torch.utils.data import DataLoader
from transformers import AdamW, get_linear_schedule_with_warmup

from brixa.ai.data.datasets.sentiment import SentimentDataset
from brixa.ai.models.sentiment import AdvancedSentimentModel
from brixa.ai.registry.registry import ModelRegistry
from brixa.core.config import settings, StorageConfig

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(settings.LOGS_DIR / "training.log")
    ]
)
logger = logging.getLogger(__name__)

def train_model(
    model: torch.nn.Module,
    train_loader: DataLoader,
    val_loader: DataLoader,
    num_epochs: int = 3,
    learning_rate: float = 2e-5,
    warmup_steps: int = 100,
    device: str = "cuda" if torch.cuda.is_available() else "cpu"
) -> dict:
    """Train the model and return training metrics."""
    model = model.to(device)
    optimizer = AdamW(model.parameters(), lr=learning_rate)
    
    # Learning rate scheduler
    total_steps = len(train_loader) * num_epochs
    scheduler = get_linear_schedule_with_warmup(
        optimizer,
        num_warmup_steps=warmup_steps,
        num_training_steps=total_steps
    )
    
    # Training loop
    metrics = {
        'train_loss': [],
        'val_loss': [],
        'val_accuracy': [],
        'learning_rates': []
    }
    
    for epoch in range(num_epochs):
        model.train()
        total_train_loss = 0
        
        for batch in train_loader:
            inputs = {k: v.to(device) for k, v in batch[0].items()}
            labels = batch[1].to(device)
            
            optimizer.zero_grad()
            outputs = model(**inputs, labels=labels)
            loss = outputs["loss"]
            loss.backward()
            
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            scheduler.step()
            
            total_train_loss += loss.item()
        
        # Calculate average training loss
        avg_train_loss = total_train_loss / len(train_loader)
        metrics['train_loss'].append(avg_train_loss)
        
        # Validation
        val_metrics = evaluate_model(model, val_loader, device)
        metrics['val_loss'].append(val_metrics['loss'])
        metrics['val_accuracy'].append(val_metrics['accuracy'])
        metrics['learning_rates'].append(scheduler.get_last_lr()[0])
        
        logger.info(
            f"Epoch {epoch + 1}/{num_epochs} | "
            f"Train Loss: {avg_train_loss:.4f} | "
            f"Val Loss: {val_metrics['loss']:.4f} | "
            f"Val Acc: {val_metrics['accuracy']:.4f}"
        )
    
    return metrics

def evaluate_model(
    model: torch.nn.Module,
    data_loader: DataLoader,
    device: str = "cuda" if torch.cuda.is_available() else "cpu"
) -> dict:
    """Evaluate the model on the given data loader."""
    model.eval()
    total_loss = 0
    total_correct = 0
    total_samples = 0
    
    with torch.no_grad():
        for batch in data_loader:
            inputs = {k: v.to(device) for k, v in batch[0].items()}
            labels = batch[1].to(device)
            
            outputs = model(**inputs, labels=labels)
            total_loss += outputs["loss"].item()
            
            # Calculate accuracy
            logits = outputs["logits"]
            predictions = torch.argmax(logits, dim=1)
            total_correct += (predictions == labels).sum().item()
            total_samples += labels.size(0)
    
    avg_loss = total_loss / len(data_loader)
    accuracy = total_correct / total_samples
    
    return {
        'loss': avg_loss,
        'accuracy': accuracy
    }

def main():
    # Initialize model registry
    registry = ModelRegistry(
        storage_node=StorageConfig.get_storage_config(),
        base_path=settings.MODEL_REGISTRY_PATH
    )
    
    # Load datasets
    train_dataset = SentimentDataset(
        data_path=settings.DATA_DIR / "sentiment",
        split="train"
    )
    val_dataset = SentimentDataset(
        data_path=settings.DATA_DIR / "sentiment",
        split="validation"
    )
    
    # Create data loaders
    train_loader = DataLoader(
        train_dataset,
        batch_size=16,
        shuffle=True,
        num_workers=2
    )
    val_loader = DataLoader(
        val_dataset,
        batch_size=16,
        shuffle=False,
        num_workers=2
    )
    
    # Initialize model
    model = AdvancedSentimentModel(
        model_name="bert-base-uncased",
        num_labels=2,
        dropout=0.1
    )
    
    # Train model
    metrics = train_model(
        model=model,
        train_loader=train_loader,
        val_loader=val_loader,
        num_epochs=3,
        learning_rate=2e-5
    )
    
    # Register model
    model_metadata = registry.register_model(
        name=settings.DEFAULT_MODEL_NAME,
        model_type="sentiment-analysis",
        framework=settings.DEFAULT_FRAMEWORK,
        description="Fine-tuned BERT model for sentiment analysis",
        metrics={
            'final_train_loss': metrics['train_loss'][-1],
            'final_val_loss': metrics['val_loss'][-1],
            'final_val_accuracy': metrics['val_accuracy'][-1]
        },
        hyperparameters={
            'learning_rate': 2e-5,
            'batch_size': 16,
            'num_epochs': 3
        }
    )
    
    # Save the trained model
    registry.save_model(
        name=settings.DEFAULT_MODEL_NAME,
        version=model_metadata.version,
        model=model
    )
    
    logger.info(f"Model training and registration complete. Version: {model_metadata.version}")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.error(f"Error in training script: {str(e)}", exc_info=True)
        sys.exit(1)
