""
AI Model Manager for Scrambled Eggs
Handles downloading, loading, and managing AI models.
"""
import os
import json
import hashlib
import requests
from pathlib import Path
from tqdm import tqdm
from typing import Optional, Dict, Any
import torch
from transformers import AutoModel, AutoTokenizer, AutoModelForSequenceClassification

class ModelManager:
    """Manages AI models for encryption and security analysis."""
    
    def __init__(self, models_dir: str = "data/models"):
        """Initialize the model manager."""
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        self.models = {}
        self._load_model_registry()
    
    def _load_model_registry(self):
        """Load the model registry from file or create default."""
        registry_file = self.models_dir / "registry.json"
        if registry_file.exists():
            with open(registry_file, 'r') as f:
                self.registry = json.load(f)
        else:
            self.registry = {
                "models": {
                    "encryption": {
                        "name": "microsoft/DialoGPT-medium",
                        "type": "encryption",
                        "version": "1.0.0",
                        "checksum": None,
                        "is_downloaded": False
                    },
                    "security_analysis": {
                        "name": "distilbert-base-uncased-finetuned-sst-2-english",
                        "type": "classification",
                        "version": "1.0.0",
                        "checksum": None,
                        "is_downloaded": False
                    },
                    "anomaly_detection": {
                        "name": "microsoft/codebert-base",
                        "type": "anomaly",
                        "version": "1.0.0",
                        "checksum": None,
                        "is_downloaded": False
                    }
                }
            }
            self._save_registry()
    
    def _save_registry(self):
        """Save the model registry to file."""
        registry_file = self.models_dir / "registry.json"
        with open(registry_file, 'w') as f:
            json.dump(self.registry, f, indent=2)
    
    def _download_file(self, url: str, file_path: Path) -> bool:
        """Download a file with progress bar."""
        try:
            response = requests.get(url, stream=True)
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            block_size = 8192
            progress_bar = tqdm(total=total_size, unit='iB', unit_scale=True)
            
            with open(file_path, 'wb') as f:
                for data in response.iter_content(block_size):
                    progress_bar.update(len(data))
                    f.write(data)
            progress_bar.close()
            
            if total_size != 0 and progress_bar.n != total_size:
                print("Error: Failed to download the file completely")
                return False
            return True
        except Exception as e:
            print(f"Error downloading file: {e}")
            return False
    
    def _calculate_checksum(self, file_path: Path) -> str:
        """Calculate SHA-256 checksum of a file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def download_model(self, model_name: str) -> bool:
        """Download a model if not already downloaded."""
        if model_name not in self.registry["models"]:
            print(f"Error: Model {model_name} not found in registry")
            return False
        
        model_info = self.registry["models"][model_name]
        model_dir = self.models_dir / model_name
        model_dir.mkdir(exist_ok=True)
        
        print(f"Downloading {model_name} model...")
        try:
            # Download model files using transformers
            if model_info["type"] == "encryption":
                model = AutoModel.from_pretrained(model_info["name"])
                tokenizer = AutoTokenizer.from_pretrained(model_info["name"])
                model.save_pretrained(model_dir)
                tokenizer.save_pretrained(model_dir)
            elif model_info["type"] == "classification":
                model = AutoModelForSequenceClassification.from_pretrained(model_info["name"])
                tokenizer = AutoTokenizer.from_pretrained(model_info["name"])
                model.save_pretrained(model_dir)
                tokenizer.save_pretrained(model_dir)
            else:
                print(f"Unsupported model type: {model_info['type']}")
                return False
            
            # Update registry
            model_info["is_downloaded"] = True
            self._save_registry()
            print(f"Successfully downloaded {model_name} model")
            return True
            
        except Exception as e:
            print(f"Error downloading model: {e}")
            return False
    
    def load_model(self, model_name: str):
        """Load a model into memory."""
        if model_name in self.models:
            return self.models[model_name]
        
        if model_name not in self.registry["models"] or not self.registry["models"][model_name]["is_downloaded"]:
            if not self.download_model(model_name):
                return None
        
        model_dir = self.models_dir / model_name
        model_info = self.registry["models"][model_name]
        
        try:
            if model_info["type"] in ["encryption", "anomaly"]:
                model = AutoModel.from_pretrained(str(model_dir))
                tokenizer = AutoTokenizer.from_pretrained(str(model_dir))
            elif model_info["type"] == "classification":
                model = AutoModelForSequenceClassification.from_pretrained(str(model_dir))
                tokenizer = AutoTokenizer.from_pretrained(str(model_dir))
            else:
                print(f"Unsupported model type: {model_info['type']}")
                return None
            
            self.models[model_name] = {
                "model": model,
                "tokenizer": tokenizer,
                "info": model_info
            }
            return self.models[model_name]
            
        except Exception as e:
            print(f"Error loading model {model_name}: {e}")
            return None
    
    def get_available_models(self) -> Dict[str, Any]:
        """Get information about available models."""
        return {
            name: {
                k: v for k, v in info.items() 
                if k in ["name", "type", "version", "is_downloaded"]
            }
            for name, info in self.registry["models"].items()
        }
