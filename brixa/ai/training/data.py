"""
Data Loading Utilities

This module provides data loading and preprocessing utilities for training AI models.
"""
import os
import json
import torch
import numpy as np
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union, Callable
from torch.utils.data import Dataset, DataLoader, DistributedSampler, RandomSampler, SequentialSampler
from torch.utils.data.distributed import DistributedSampler
from torchvision import transforms
import logging

logger = logging.getLogger(__name__)

class BaseDataset(Dataset):
    """Base dataset class for handling data loading and preprocessing."""
    
    def __init__(
        self, 
        data_dir: str,
        split: str = "train",
        transform: Optional[Callable] = None,
        target_transform: Optional[Callable] = None,
        **kwargs
    ):
        """Initialize the dataset.
        
        Args:
            data_dir: Directory containing the dataset
            split: Dataset split ('train', 'val', 'test')
            transform: Optional transform to apply to the data
            target_transform: Optional transform to apply to the labels/targets
            **kwargs: Additional dataset-specific arguments
        """
        self.data_dir = Path(data_dir)
        self.split = split
        self.transform = transform
        self.target_transform = target_transform
        self.data = []
        self.targets = []
        
        # Load the dataset
        self._load_data()
    
    def _load_data(self) -> None:
        """Load the dataset into memory."""
        raise NotImplementedError("Subclasses must implement _load_data()")
    
    def __len__(self) -> int:
        """Return the number of samples in the dataset."""
        return len(self.data)
    
    def __getitem__(self, idx: int) -> Tuple[Any, Any]:
        """Get a sample from the dataset.
        
        Args:
            idx: Index of the sample to retrieve
            
        Returns:
            Tuple of (data, target) where target is the label/target value
        """
        data = self.data[idx]
        target = self.targets[idx] if self.targets is not None else None
        
        # Apply transforms if specified
        if self.transform is not None:
            data = self.transform(data)
            
        if self.target_transform is not None and target is not None:
            target = self.target_transform(target)
        
        if target is not None:
            return data, target
        return data


def get_data_loaders(
    dataset_class: type,
    data_dir: str,
    batch_size: int = 32,
    num_workers: int = 4,
    distributed: bool = False,
    **dataset_kwargs
) -> Dict[str, DataLoader]:
    """Create data loaders for training, validation, and testing.
    
    Args:
        dataset_class: Dataset class to use
        data_dir: Directory containing the dataset
        batch_size: Batch size for the data loaders
        num_workers: Number of worker processes for data loading
        distributed: Whether to use distributed training
        **dataset_kwargs: Additional arguments to pass to the dataset constructor
        
    Returns:
        Dictionary containing data loaders for each split
    """
    # Define transforms
    train_transform = transforms.Compose([
        transforms.RandomHorizontalFlip(),
        transforms.RandomCrop(32, padding=4),
        transforms.ToTensor(),
        transforms.Normalize((0.5,), (0.5,)),
    ])
    
    test_transform = transforms.Compose([
        transforms.ToTensor(),
        transforms.Normalize((0.5,), (0.5,)),
    ])
    
    # Create datasets
    train_dataset = dataset_class(
        data_dir=data_dir,
        split='train',
        transform=train_transform,
        **dataset_kwargs
    )
    
    val_dataset = dataset_class(
        data_dir=data_dir,
        split='val',
        transform=test_transform,
        **dataset_kwargs
    )
    
    test_dataset = dataset_class(
        data_dir=data_dir,
        split='test',
        transform=test_transform,
        **dataset_kwargs
    )
    
    # Create samplers
    if distributed:
        train_sampler = DistributedSampler(train_dataset)
        val_sampler = DistributedSampler(val_dataset, shuffle=False)
        test_sampler = DistributedSampler(test_dataset, shuffle=False)
    else:
        train_sampler = RandomSampler(train_dataset)
        val_sampler = SequentialSampler(val_dataset)
        test_sampler = SequentialSampler(test_dataset)
    
    # Create data loaders
    train_loader = DataLoader(
        train_dataset,
        batch_size=batch_size,
        sampler=train_sampler,
        num_workers=num_workers,
        pin_memory=True,
        drop_last=True,
    )
    
    val_loader = DataLoader(
        val_dataset,
        batch_size=batch_size,
        sampler=val_sampler,
        num_workers=num_workers,
        pin_memory=True,
    )
    
    test_loader = DataLoader(
        test_dataset,
        batch_size=batch_size,
        sampler=test_sampler,
        num_workers=num_workers,
        pin_memory=True,
    )
    
    return {
        'train': train_loader,
        'val': val_loader,
        'test': test_loader,
        'train_sampler': train_sampler,
    }


def collate_fn(batch):
    """Custom collate function for handling variable-length sequences."""
    # Unzip the batch
    if isinstance(batch[0], (tuple, list)):
        transposed = list(zip(*batch))
        return [collate_fn(samples) for samples in transposed]
    
    # Handle tensors
    if isinstance(batch[0], torch.Tensor):
        # Stack tensors along the first dimension
        return torch.stack(batch, 0)
    
    # Handle numpy arrays
    if isinstance(batch[0], np.ndarray):
        return torch.stack([torch.from_numpy(b) for b in batch], 0)
    
    # Handle numbers
    if isinstance(batch[0], (int, float)):
        return torch.tensor(batch)
    
    # Handle strings
    if isinstance(batch[0], str):
        return batch
    
    # Handle dictionaries
    if isinstance(batch[0], dict):
        return {key: collate_fn([d[key] for d in batch]) for key in batch[0]}
    
    # Default: return as is
    return batch


def worker_init_fn(worker_id: int) -> None:
    """Worker init function to ensure different random seeds for each worker."""
    worker_seed = torch.initial_seed() % 2**32
    np.random.seed(worker_seed)
    
    # Set different seeds for file operations
    import random
    random.seed(worker_seed)
    
    # Set different seeds for other libraries if needed
    # torch.manual_seed(worker_seed)
    # torch.cuda.manual_seed(worker_seed)
