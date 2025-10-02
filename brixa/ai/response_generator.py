"""
Response Generator Module

This module handles generating responses using language models,
including context management, response formatting, and safety checks.
"""
from typing import Dict, List, Optional, Any, Union, Tuple
import json
import re
import logging
from datetime import datetime

from .llm import get_llm, BaseLLM

logger = logging.getLogger(__name__)

class ResponseGenerator:
    """Handles generating responses using language models."""
    
    def __init__(
        self,
        model_name: str = "gpt-4",
        model_type: str = "openai",
        system_prompt: Optional[str] = None,
        **model_kwargs
    ):
        """Initialize the response generator.
        
        Args:
            model_name: Name of the language model to use
            model_type: Type of model ('openai', 'local', etc.)
            system_prompt: Optional system prompt to prepend to all conversations
            **model_kwargs: Additional model-specific parameters
        """
        self.model_name = model_name
        self.model_type = model_type
        self.system_prompt = system_prompt or """You are Clippy, a helpful AI assistant. 
You provide concise, accurate, and helpful responses. Be friendly and professional.
"""
        self.model_kwargs = model_kwargs
        self._llm: Optional[BaseLLM] = None
        
    async def initialize(self):
        """Initialize the language model."""
        if self._llm is None:
            self._llm = get_llm(
                model_name=self.model_name,
                model_type=self.model_type,
                **self.model_kwargs
            )
            await self._llm.initialize()
            
    async def generate_response(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int = 2000,
        temperature: float = 0.7,
        **kwargs
    ) -> Dict[str, Any]:
        """Generate a response to a conversation.
        
        Args:
            messages: List of message dicts with 'role' and 'content'
            max_tokens: Maximum number of tokens to generate
            temperature: Sampling temperature
            **kwargs: Additional generation parameters
            
        Returns:
            Dictionary containing the response and metadata
        """
        if not self._llm:
            await self.initialize()
            
        try:
            # Format messages for the model
            formatted_messages = self._format_messages(messages)
            
            # Generate response
            start_time = datetime.now()
            response = await self._llm.generate(
                prompt=formatted_messages,
                max_tokens=max_tokens,
                temperature=temperature,
                **kwargs
            )
            end_time = datetime.now()
            
            # Process and clean the response
            response = self._clean_response(response)
            
            return {
                'response': response,
                'metadata': {
                    'model': self.model_name,
                    'tokens_generated': len(response.split()),
                    'processing_time': (end_time - start_time).total_seconds(),
                    'timestamp': end_time.isoformat()
                }
            }
            
        except Exception as e:
            logger.error(f"Error generating response: {e}")
            return {
                'response': "I'm sorry, I encountered an error while generating a response.",
                'error': str(e),
                'metadata': {
                    'model': self.model_name,
                    'error': True,
                    'timestamp': datetime.utcnow().isoformat()
                }
            }
    
    def _format_messages(self, messages: List[Dict[str, str]]) -> str:
        """Format messages into a single prompt string."""
        formatted = []
        
        # Add system prompt if this is the first message
        if self.system_prompt and (not messages or messages[0]['role'] != 'system'):
            formatted.append(f"System: {self.system_prompt}")
            
        for msg in messages:
            role = msg['role'].capitalize()
            content = msg['content']
            formatted.append(f"{role}: {content}")
            
        return "\n".join(formatted) + "\nAssistant: "
    
    def _clean_response(self, response: str) -> str:
        """Clean and format the model's response."""
        # Remove any trailing whitespace and newlines
        response = response.strip()
        
        # Remove any remaining role prefixes if present
        response = re.sub(r'^(Assistant|AI|Bot):\s*', '', response, flags=re.IGNORECASE)
        
        # Ensure proper sentence casing and spacing
        response = re.sub(r'\.\s+([a-z])', lambda m: f". {m.group(1).upper()}", response)
        
        return response
    
    async def stream_response(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int = 2000,
        temperature: float = 0.7,
        **kwargs
    ) -> str:
        """Stream the response token by token.
        
        Args:
            messages: List of message dicts with 'role' and 'content'
            max_tokens: Maximum number of tokens to generate
            temperature: Sampling temperature
            **kwargs: Additional generation parameters
            
        Yields:
            Tokens as they are generated
        """
        if not self._llm:
            await self.initialize()
            
        # This is a simplified version - in a real implementation, you would
        # use the model's streaming API if available
        response = await self.generate_response(
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature,
            **kwargs
        )
        
        # Simulate streaming by yielding tokens
        for token in response['response'].split():
            yield token + " "
            
    async def get_embeddings(self, text: str) -> List[float]:
        """Get embeddings for the given text.
        
        Args:
            text: Input text to get embeddings for
            
        Returns:
            List of floating-point numbers representing the text embedding
        """
        if not self._llm:
            await self.initialize()
            
        # This is a placeholder - implement actual embedding generation
        # based on the model's capabilities
        if hasattr(self._llm, 'get_embeddings'):
            return await self._llm.get_embeddings(text)
        else:
            # Fallback to a simple hash-based embedding for demonstration
            import hashlib
            import numpy as np
            
            # Generate a deterministic hash of the text
            hash_obj = hashlib.sha256(text.encode())
            hash_bytes = hash_obj.digest()
            
            # Convert to a list of floats between -1 and 1
            return [
                (int.from_bytes(hash_bytes[i:i+4], byteorder='little') / 2**32) * 2 - 1
                for i in range(0, min(384, len(hash_bytes)), 4)
            ]
