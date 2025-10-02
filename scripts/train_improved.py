""
Improved Training Script

This script demonstrates training with early stopping, learning rate scheduling,
and gradient accumulation for better model performance.
"""
import os
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, random_split
from torch.optim.lr_scheduler import ReduceLROnPlateau
import numpy as np
from pathlib import Path
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import your model and data loading code
from brixa.ai.models.sentiment import SentimentClassifier
from brixa.ai.data.datasets import SentimentDataset
from brixa.ai.training import TrainingMetrics

def train_epoch(model, train_loader, criterion, optimizer, device, accumulation_steps=1):
    """Train the model for one epoch with gradient accumulation."""
    model.train()
    total_loss = 0
    correct = 0
    total = 0
    
    optimizer.zero_grad()
    
    for i, (inputs, labels) in enumerate(train_loader):
        inputs, labels = inputs.to(device), labels.to(device)
        
        # Forward pass
        outputs = model(inputs)
        loss = criterion(outputs, labels)
        
        # Scale loss for gradient accumulation
        loss = loss / accumulation_steps
        
        # Backward pass and optimize
        loss.backward()
        
        # Perform optimization step only after accumulating enough gradients
        if (i + 1) % accumulation_steps == 0 or (i + 1) == len(train_loader):
            optimizer.step()
            optimizer.zero_grad()
        
        # Calculate metrics
        total_loss += loss.item() * accumulation_steps
        _, predicted = torch.max(outputs.data, 1)
        total += labels.size(0)
        correct += (predicted == labels).sum().item()
    
    avg_loss = total_loss / len(train_loader)
    accuracy = 100 * correct / total
    
    return avg_loss, accuracy

def validate(model, val_loader, criterion, device):
    """Validate the model on the validation set."""
    model.eval()
    total_loss = 0
    correct = 0
    total = 0
    
    with torch.no_grad():
        for inputs, labels in val_loader:
            inputs, labels = inputs.to(device), labels.to(device)
            
            outputs = model(inputs)
            loss = criterion(outputs, labels)
            
            total_loss += loss.item()
            _, predicted = torch.max(outputs.data, 1)
            total += labels.size(0)
            correct += (predicted == labels).sum().item()
    
    avg_loss = total_loss / len(val_loader)
    accuracy = 100 * correct / total
    
    return avg_loss, accuracy

def train_model(
    model,
    train_loader,
    val_loader,
    criterion,
    optimizer,
    scheduler,
    device,
    num_epochs=10,
    patience=3,
    accumulation_steps=1,
    checkpoint_dir='checkpoints',
    model_name='sentiment_model'
):
    """Train the model with early stopping and model checkpointing."""
    # Create checkpoint directory
    checkpoint_dir = Path(checkpoint_dir)
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    
    best_val_loss = float('inf')
    epochs_no_improve = 0
    
    # Initialize metrics
    metrics = TrainingMetrics()
    
    for epoch in range(num_epochs):
        logger.info(f'Epoch {epoch+1}/{num_epochs}')
        
        # Train for one epoch
        train_loss, train_acc = train_epoch(
            model, train_loader, criterion, optimizer, 
            device, accumulation_steps
        )
        
        # Validate
        val_loss, val_acc = validate(model, val_loader, criterion, device)
        
        # Step the scheduler
        if isinstance(scheduler, ReduceLROnPlateau):
            scheduler.step(val_loss)
        else:
            scheduler.step()
        
        # Update metrics
        metrics.update(
            loss=train_loss,
            accuracy=train_acc,
            val_loss=val_loss,
            val_accuracy=val_acc,
            lr=optimizer.param_groups[0]['lr']
        )
        
        logger.info(
            f'Train Loss: {train_loss:.4f}, Train Acc: {train_acc:.2f}% | '
            f'Val Loss: {val_loss:.4f}, Val Acc: {val_acc:.2f}% | '
            f'LR: {optimizer.param_groups[0]["lr"]:.2e}'
        )
        
        # Check for improvement
        if val_loss < best_val_loss:
            logger.info(f'Validation loss improved from {best_val_loss:.4f} to {val_loss:.4f}')
            best_val_loss = val_loss
            epochs_no_improve = 0
            
            # Save best model
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            model_path = checkpoint_dir / f'{model_name}_best.pt'
            torch.save({
                'epoch': epoch,
                'model_state_dict': model.state_dict(),
                'optimizer_state_dict': optimizer.state_dict(),
                'val_loss': val_loss,
                'val_accuracy': val_acc,
                'metrics': metrics.to_dict(),
                'version': '1.0.0',
            }, model_path)
            logger.info(f'Saved best model to {model_path}')
        else:
            epochs_no_improve += 1
            logger.info(f'No improvement in validation loss for {epochs_no_improve} epochs')
            
            # Early stopping
            if epochs_no_improve >= patience:
                logger.info(f'Early stopping after {epoch+1} epochs')
                break
    
    return metrics

def main():
    # Configuration
    config = {
        'batch_size': 32,
        'num_epochs': 20,
        'learning_rate': 1e-3,
        'weight_decay': 1e-5,
        'patience': 5,
        'accumulation_steps': 4,
        'model_name': 'sentiment_improved',
        'checkpoint_dir': 'checkpoints',
    }
    
    # Set device
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    logger.info(f'Using device: {device}')
    
    # Initialize model
    model = SentimentClassifier()
    model.to(device)
    
    # Load dataset (replace with your actual dataset)
    # dataset = SentimentDataset(...)
    # train_size = int(0.8 * len(dataset))
    # val_size = len(dataset) - train_size
    # train_dataset, val_dataset = random_split(dataset, [train_size, val_size])
    # train_loader = DataLoader(train_dataset, batch_size=config['batch_size'], shuffle=True)
    # val_loader = DataLoader(val_dataset, batch_size=config['batch_size'])
    
    # For now, we'll use dummy data
    # TODO: Replace with actual data loading
    logger.warning('Using dummy data for demonstration. Replace with actual dataset.')
    train_loader = [
        (torch.randn(32, 100), torch.randint(0, 2, (32,))) 
        for _ in range(100)
    ]
    val_loader = [
        (torch.randn(32, 100), torch.randint(0, 2, (32,)))
        for _ in range(20)
    ]
    
    # Initialize loss function and optimizer
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.AdamW(
        model.parameters(),
        lr=config['learning_rate'],
        weight_decay=config['weight_decay']
    )
    
    # Learning rate scheduler
    scheduler = ReduceLROnPlateau(
        optimizer,
        mode='min',
        factor=0.5,
        patience=2,
        verbose=True
    )
    
    # Train the model
    metrics = train_model(
        model=model,
        train_loader=train_loader,
        val_loader=val_loader,
        criterion=criterion,
        optimizer=optimizer,
        scheduler=scheduler,
        device=device,
        num_epochs=config['num_epochs'],
        patience=config['patience'],
        accumulation_steps=config['accumulation_steps'],
        checkpoint_dir=config['checkpoint_dir'],
        model_name=config['model_name']
    )
    
    logger.info('Training completed')

if __name__ == '__main__':
    main()
