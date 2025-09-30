"""
Language Model Module

This module provides interfaces and implementations for various language models
that can be used with the Clippy AI assistant.
"""
from typing import Dict, List, Optional, Any, Union
from abc import ABC, abstractmethod
import logging

logger = logging.getLogger(__name__)

class BaseLLM(ABC):
    """Base class for all language models."""
    
    def __init__(self, model_name: str, **kwargs):
        """Initialize the language model.
        
        Args:
            model_name: Name of the model to use
            **kwargs: Additional model-specific parameters
        """
        self.model_name = model_name
        self._is_initialized = False
        
    @abstractmethod
    async def initialize(self):
        """Initialize the model (load weights, etc.)."""
        pass
        
    @abstractmethod
    async def generate(
        self, 
        prompt: str, 
        max_tokens: int = 2000, 
        temperature: float = 0.7,
        **kwargs
    ) -> str:
        """Generate text from the model.
        
        Args:
            prompt: Input prompt
            max_tokens: Maximum number of tokens to generate
            temperature: Sampling temperature
            **kwargs: Additional generation parameters
            
        Returns:
            Generated text
        """
        pass
        
    @property
    def is_initialized(self) -> bool:
        """Check if the model is initialized."""
        return self._is_initialized


class OpenAIModel(BaseLLM):
    """Wrapper for OpenAI's language models."""
    
    def __init__(self, model_name: str = "gpt-4", api_key: Optional[str] = None):
        """Initialize the OpenAI model.
        
        Args:
            model_name: Name of the OpenAI model to use
            api_key: OpenAI API key (if not provided, will use OPENAI_API_KEY env var)
        """
        super().__init__(model_name)
        self.api_key = api_key
        self._client = None
        
    async def initialize(self):
        """Initialize the OpenAI client."""
        try:
            from openai import AsyncOpenAI
            self._client = AsyncOpenAI(api_key=self.api_key)
            self._is_initialized = True
            logger.info(f"Initialized OpenAI model: {self.model_name}")
        except ImportError:
            logger.error("OpenAI package not installed. Install with: pip install openai")
            raise
            
    async def generate(
        self, 
        prompt: str, 
        max_tokens: int = 2000, 
        temperature: float = 0.7,
        **kwargs
    ) -> str:
        """Generate text using the OpenAI API."""
        if not self._is_initialized:
            await self.initialize()
            
        try:
            response = await self._client.chat.completions.create(
                model=self.model_name,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=max_tokens,
                temperature=temperature,
                **kwargs
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"Error generating text: {e}")
            raise


class LocalLLM(BaseLLM):
    """Wrapper for locally hosted language models."""
    
    def __init__(self, model_name: str, model_path: Optional[str] = None):
        """Initialize the local model.
        
        Args:
            model_name: Name of the model
            model_path: Path to the model weights (if not in default location)
        """
        super().__init__(model_name)
        self.model_path = model_path
        self._model = None
        self._tokenizer = None
        
    async def initialize(self):
        """Load the model and tokenizer."""
        try:
            from transformers import AutoModelForCausalLM, AutoTokenizer
            import torch
            
            device = "cuda" if torch.cuda.is_available() else "cpu"
            logger.info(f"Loading model {self.model_name} on {device}...")
            
            self._tokenizer = AutoTokenizer.from_pretrained(
                self.model_path or self.model_name
            )
            self._model = AutoModelForCausalLM.from_pretrained(
                self.model_path or self.model_name,
                torch_dtype=torch.float16 if device == "cuda" else torch.float32,
                low_cpu_mem_usage=True
            ).to(device)
            
            self._is_initialized = True
            logger.info(f"Initialized local model: {self.model_name}")
            
        except ImportError:
            logger.error("Transformers package not installed. Install with: pip install transformers")
            raise
            
    async def generate(
        self, 
        prompt: str, 
        max_tokens: int = 2000, 
        temperature: float = 0.7,
        **kwargs
    ) -> str:
        """Generate text using the local model."""
        if not self._is_initialized:
            await self.initialize()
            
        try:
            inputs = self._tokenizer(prompt, return_tensors="pt").to(self._model.device)
            outputs = self._model.generate(
                **inputs,
                max_new_tokens=max_tokens,
                temperature=temperature,
                do_sample=True,
                **kwargs
            )
            return self._tokenizer.decode(outputs[0], skip_special_tokens=True)
        except Exception as e:
            logger.error(f"Error generating text: {e}")
            raise


def get_llm(
    model_name: str, 
    model_type: str = "openai", 
    **kwargs
) -> BaseLLM:
    """Factory function to get a language model.
    
    Args:
        model_name: Name of the model to use
        model_type: Type of model ('openai', 'local', etc.)
        **kwargs: Additional model-specific parameters
        
    Returns:
        An instance of the requested language model
    """
    if model_type == "openai":
        return OpenAIModel(model_name, **kwargs)
    elif model_type == "local":
        return LocalLLM(model_name, **kwargs)
    else:
        raise ValueError(f"Unknown model type: {model_type}")
