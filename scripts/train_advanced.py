""
Advanced Training Script

This script includes mixed precision training, improved validation,
and advanced training techniques for better model performance.
"""
import os
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, random_split, Dataset
from torch.optim.lr_scheduler import OneCycleLR, ReduceLROnPlateau
from torch.cuda.amp import GradScaler, autocast
import numpy as np
from pathlib import Path
import logging
from datetime import datetime
from typing import Optional, Dict, Any, Tuple, List, Union

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('training.log')
    ]
)
logger = logging.getLogger(__name__)

# Import your model and data loading code
from brixa.ai.models.sentiment import SentimentClassifier
from brixa.ai.data.datasets import SentimentDataset
from brixa.ai.training import TrainingMetrics

class AdvancedTrainer:
    """Advanced trainer with mixed precision and advanced techniques."""
    
    def __init__(
        self,
        model: nn.Module,
        train_loader: DataLoader,
        val_loader: DataLoader,
        criterion: nn.Module,
        optimizer: optim.Optimizer,
        device: torch.device,
        config: Optional[Dict[str, Any]] = None
    ):
        """Initialize the advanced trainer."""
        self.model = model
        self.train_loader = train_loader
        self.val_loader = val_loader
        self.criterion = criterion
        self.optimizer = optimizer
        self.device = device
        self.config = self._get_default_config()
        if config:
            self.config.update(config)
        
        # Mixed precision training
        self.scaler = GradScaler(enabled=self.config['use_amp'])
        
        # Learning rate scheduler
        self.scheduler = self._create_scheduler()
        
        # Training state
        self.epoch = 0
        self.best_metric = float('inf' if self.config['metric_mode'] == 'min' else '-inf')
        self.metrics = TrainingMetrics()
        
        # Create checkpoint directory
        self.checkpoint_dir = Path(self.config['checkpoint_dir'])
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default training configuration."""
        return {
            'num_epochs': 20,
            'patience': 5,
            'accumulation_steps': 4,
            'grad_clip': 1.0,
            'use_amp': True,
            'checkpoint_dir': 'checkpoints',
            'model_name': 'sentiment_advanced',
            'metric': 'val_loss',
            'metric_mode': 'min',  # 'min' for loss, 'max' for accuracy
            'scheduler_config': {
                'name': 'plateau',
                'mode': 'min',
                'factor': 0.5,
                'patience': 2,
                'verbose': True,
                'min_lr': 1e-6,
            },
            'log_interval': 10,
        }
    
    def _create_scheduler(self):
        """Create learning rate scheduler."""
        sched_config = self.config['scheduler_config']
        
        if sched_config['name'] == 'plateau':
            return ReduceLROnPlateau(
                self.optimizer,
                mode=sched_config['mode'],
                factor=sched_config['factor'],
                patience=sched_config['patience'],
                verbose=sched_config['verbose'],
                min_lr=sched_config['min_lr']
            )
        elif sched_config['name'] == 'onecycle':
            return OneCycleLR(
                self.optimizer,
                max_lr=self.optimizer.param_groups[0]['lr'],
                epochs=self.config['num_epochs'],
                steps_per_epoch=len(self.train_loader)
            )
        return None
    
    def _train_epoch(self) -> Tuple[float, float]:
        """Train for one epoch with mixed precision and gradient accumulation."""
        self.model.train()
        total_loss = 0.0
        correct = 0
        total = 0
        
        self.optimizer.zero_grad()
        
        for batch_idx, (inputs, labels) in enumerate(self.train_loader):
            inputs, labels = inputs.to(self.device), labels.to(self.device)
            
            with autocast(enabled=self.config['use_amp']):
                outputs = self.model(inputs)
                loss = self.criterion(outputs, labels) / self.config['accumulation_steps']
            
            # Scale loss and backpropagate
            self.scaler.scale(loss).backward()
            
            # Gradient accumulation
            if (batch_idx + 1) % self.config['accumulation_steps'] == 0 or (batch_idx + 1) == len(self.train_loader):
                # Gradient clipping
                self.scaler.unscale_(self.optimizer)
                torch.nn.utils.clip_grad_norm_(
                    self.model.parameters(), 
                    max_norm=self.config['grad_clip']
                )
                
                # Optimizer step
                self.scaler.step(self.optimizer)
                self.scaler.update()
                self.optimizer.zero_grad()
                
                # Step the scheduler if using OneCycleLR
                if isinstance(self.scheduler, OneCycleLR):
                    self.scheduler.step()
            
            # Calculate metrics
            total_loss += loss.item() * self.config['accumulation_steps']
            _, predicted = torch.max(outputs.data, 1)
            total += labels.size(0)
            correct += (predicted == labels).sum().item()
            
            # Log progress
            if (batch_idx + 1) % self.config['log_interval'] == 0:
                logger.info(
                    f'Train Epoch: {self.epoch} [{batch_idx * len(inputs)}/{len(self.train_loader.dataset)} '
                    f'({100. * batch_idx / len(self.train_loader):.0f}%)]\t'
                    f'Loss: {loss.item():.6f}'
                )
        
        avg_loss = total_loss / len(self.train_loader)
        accuracy = 100 * correct / total
        
        return avg_loss, accuracy
    
    @torch.no_grad()
    def _validate(self) -> Tuple[float, float]:
        """Validate the model on the validation set."""
        self.model.eval()
        total_loss = 0.0
        correct = 0
        total = 0
        
        for inputs, labels in self.val_loader:
            inputs, labels = inputs.to(self.device), labels.to(self.device)
            
            with autocast(enabled=self.config['use_amp']):
                outputs = self.model(inputs)
                loss = self.criterion(outputs, labels)
            
            total_loss += loss.item()
            _, predicted = torch.max(outputs.data, 1)
            total += labels.size(0)
            correct += (predicted == labels).sum().item()
        
        avg_loss = total_loss / len(self.val_loader)
        accuracy = 100 * correct / total
        
        return avg_loss, accuracy
    
    def _save_checkpoint(self, is_best: bool = False):
        """Save model checkpoint."""
        checkpoint = {
            'epoch': self.epoch,
            'model_state_dict': self.model.state_dict(),
            'optimizer_state_dict': self.optimizer.state_dict(),
            'scheduler_state_dict': self.scheduler.state_dict() if self.scheduler else None,
            'scaler_state_dict': self.scaler.state_dict(),
            'metrics': self.metrics.to_dict(),
            'config': self.config,
            'val_loss': self.metrics.val_loss[-1] if self.metrics.val_loss else None,
            'val_accuracy': self.metrics.val_accuracy[-1] if self.metrics.val_accuracy else None,
        }
        
        # Save latest checkpoint
        torch.save(checkpoint, self.checkpoint_dir / f"{self.config['model_name']}_latest.pt")
        
        # Save best checkpoint
        if is_best:
            torch.save(checkpoint, self.checkpoint_dir / f"{self.config['model_name']}_best.pt")
    
    def train(self) -> TrainingMetrics:
        """Run the training loop."""
        epochs_no_improve = 0
        
        for epoch in range(self.config['num_epochs']):
            self.epoch = epoch
            logger.info(f'Epoch {epoch+1}/{self.config["num_epochs"]}')
            
            # Train for one epoch
            train_loss, train_acc = self._train_epoch()
            
            # Validate
            val_loss, val_acc = self._validate()
            
            # Step the scheduler if using ReduceLROnPlateau
            if isinstance(self.scheduler, ReduceLROnPlateau):
                self.scheduler.step(val_loss)
            
            # Update metrics
            self.metrics.update(
                loss=train_loss,
                accuracy=train_acc,
                val_loss=val_loss,
                val_accuracy=val_acc,
                lr=self.optimizer.param_groups[0]['lr']
            )
            
            # Log metrics
            logger.info(
                f'Train Loss: {train_loss:.4f}, Train Acc: {train_acc:.2f}% | '
                f'Val Loss: {val_loss:.4f}, Val Acc: {val_acc:.2f}% | '
                f'LR: {self.optimizer.param_groups[0]["lr"]:.2e}'
            )
            
            # Check for improvement
            current_metric = val_loss if self.config['metric'] == 'val_loss' else val_acc
            is_better = (
                current_metric < self.best_metric 
                if self.config['metric_mode'] == 'min' 
                else current_metric > self.best_metric
            )
            
            if is_better:
                logger.info(f'Metric improved from {self.best_metric:.4f} to {current_metric:.4f}')
                self.best_metric = current_metric
                epochs_no_improve = 0
                self._save_checkpoint(is_best=True)
            else:
                epochs_no_improve += 1
                logger.info(f'No improvement in metric for {epochs_no_improve} epochs')
                self._save_checkpoint()
                
                # Early stopping
                if epochs_no_improve >= self.config['patience']:
                    logger.info(f'Early stopping after {epoch+1} epochs')
                    break
        
        return self.metrics

def main():
    # Configuration
    config = {
        'num_epochs': 30,
        'batch_size': 32,
        'learning_rate': 1e-3,
        'weight_decay': 1e-5,
        'patience': 7,
        'accumulation_steps': 4,
        'grad_clip': 1.0,
        'use_amp': True,
        'model_name': 'sentiment_advanced',
        'checkpoint_dir': 'checkpoints',
        'metric': 'val_loss',
        'metric_mode': 'min',
        'scheduler_config': {
            'name': 'plateau',  # 'plateau' or 'onecycle'
            'mode': 'min',
            'factor': 0.5,
            'patience': 2,
            'verbose': True,
            'min_lr': 1e-6,
        },
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
    logger.warning('Using dummy data for demonstration. Replace with actual dataset.')
    class DummyDataset(Dataset):
        def __init__(self, size=1000, seq_len=100, num_classes=2):
            self.data = torch.randn(size, seq_len)
            self.targets = torch.randint(0, num_classes, (size,))
        
        def __len__(self):
            return len(self.data)
        
        def __getitem__(self, idx):
            return self.data[idx], self.targets[idx]
    
    dataset = DummyDataset()
    train_size = int(0.8 * len(dataset))
    val_size = len(dataset) - train_size
    train_dataset, val_dataset = random_split(dataset, [train_size, val_size])
    train_loader = DataLoader(train_dataset, batch_size=config['batch_size'], shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=config['batch_size'])
    
    # Initialize loss function and optimizer
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.AdamW(
        model.parameters(),
        lr=config['learning_rate'],
        weight_decay=config['weight_decay']
    )
    
    # Initialize trainer
    trainer = AdvancedTrainer(
        model=model,
        train_loader=train_loader,
        val_loader=val_loader,
        criterion=criterion,
        optimizer=optimizer,
        device=device,
        config=config
    )
    
    # Train the model
    metrics = trainer.train()
    
    logger.info('Training completed')

if __name__ == '__main__':
    main()
