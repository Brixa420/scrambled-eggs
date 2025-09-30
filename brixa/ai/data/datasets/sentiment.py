from torch.utils.data import Dataset
from typing import List, Dict, Tuple, Optional
import torch
from pathlib import Path
import json
from transformers import AutoTokenizer

class SentimentDataset(Dataset):
    """Dataset for sentiment analysis tasks."""
    
    def __init__(
        self,
        data_path: str,
        tokenizer_name: str = "bert-base-uncased",
        max_length: int = 128,
        split: str = "train",
        augment: bool = False
    ):
        self.tokenizer = AutoTokenizer.from_pretrained(tokenizer_name)
        self.max_length = max_length
        self.augment = augment
        self.data = self._load_data(data_path, split)
    
    def _load_data(self, data_path: str, split: str) -> List[Dict]:
        """Load and preprocess the dataset."""
        data_path = Path(data_path) / f"{split}.json"
        with open(data_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data
    
    def _tokenize(self, text: str) -> Dict[str, torch.Tensor]:
        """Tokenize text and return model inputs."""
        return self.tokenizer(
            text,
            max_length=self.max_length,
            padding="max_length",
            truncation=True,
            return_tensors="pt"
        )
    
    def _augment(self, text: str) -> str:
        """Apply text augmentation if enabled."""
        if not self.augment:
            return text
        # Add your data augmentation logic here
        return text
    
    def __len__(self) -> int:
        return len(self.data)
    
    def __getitem__(self, idx: int) -> Tuple[Dict[str, torch.Tensor], int]:
        item = self.data[idx]
        text = self._augment(item["text"])
        label = item["label"]
        
        # Tokenize text
        inputs = self._tokenize(text)
        
        # Convert to tensors
        return {
            "input_ids": inputs["input_ids"].squeeze(0),
            "attention_mask": inputs["attention_mask"].squeeze(0)
        }, torch.tensor(label, dtype=torch.long)
