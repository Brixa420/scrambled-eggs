"""
Secure AI Service

This module provides secure AI operations with encrypted data handling.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional, Union

from app.core.security import SecurityManager
from app.services.scrambled_eggs_crypto import EncryptionResult, ScrambledEggsCrypto

logger = logging.getLogger(__name__)


@dataclass
class AIRequest:
    """Represents an AI request with encrypted data."""

    request_id: str
    model: str
    encrypted_prompt: bytes
    parameters: Dict[str, Any]
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert to a serializable dictionary."""
        return {
            "request_id": self.request_id,
            "model": self.model,
            "encrypted_prompt": self.encrypted_prompt.hex(),
            "parameters": self.parameters,
            "metadata": self.metadata,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AIRequest":
        """Create from a dictionary."""
        return cls(
            request_id=data["request_id"],
            model=data["model"],
            encrypted_prompt=bytes.fromhex(data["encrypted_prompt"]),
            parameters=data.get("parameters", {}),
            metadata=data.get("metadata", {}),
            created_at=data.get("created_at", datetime.utcnow().isoformat()),
        )


@dataclass
class AIResponse:
    """Represents an AI response with encrypted data."""

    request_id: str
    model: str
    encrypted_response: bytes
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert to a serializable dictionary."""
        return {
            "request_id": self.request_id,
            "model": self.model,
            "encrypted_response": self.encrypted_response.hex(),
            "metadata": self.metadata,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AIResponse":
        """Create from a dictionary."""
        return cls(
            request_id=data["request_id"],
            model=data["model"],
            encrypted_response=bytes.fromhex(data["encrypted_response"]),
            metadata=data.get("metadata", {}),
            created_at=data.get("created_at", datetime.utcnow().isoformat()),
        )


class SecureAIService:
    """Provides secure AI operations with encrypted data handling."""

    def __init__(
        self,
        security_manager: Optional[SecurityManager] = None,
        crypto_service: Optional[ScrambledEggsCrypto] = None,
    ):
        """Initialize the secure AI service."""
        self.security_manager = security_manager or SecurityManager()
        self.crypto = crypto_service or ScrambledEggsCrypto(self.security_manager)

        # AI model configuration
        self.available_models = {
            "gpt-4": {"max_tokens": 8192, "supports_streaming": True, "encryption_required": True},
            "claude-3-opus": {
                "max_tokens": 100000,
                "supports_streaming": True,
                "encryption_required": True,
            },
            "llama-3": {
                "max_tokens": 4096,
                "supports_streaming": False,
                "encryption_required": True,
            },
        }

        # Initialize model providers
        self.model_providers = {}
        self._initialize_providers()

    def _initialize_providers(self) -> None:
        """Initialize AI model providers."""
        try:
            # Try to import and initialize OpenAI provider if available
            try:
                from .providers.openai_provider import OpenAIProvider

                self.model_providers["openai"] = OpenAIProvider()
            except ImportError:
                logger.warning("OpenAI provider not available. Install with 'pip install openai'")

            # Try to import and initialize Anthropic provider if available
            try:
                from .providers.anthropic_provider import AnthropicProvider

                self.model_providers["anthropic"] = AnthropicProvider()
            except ImportError:
                logger.warning(
                    "Anthropic provider not available. Install with 'pip install anthropic'"
                )

            # Add more providers as needed

        except Exception as e:
            logger.error(f"Failed to initialize AI providers: {e}")

    def get_available_models(self) -> Dict[str, Dict[str, Any]]:
        """Get a list of available AI models and their capabilities."""
        return self.available_models

    def _get_model_provider(self, model_name: str) -> Any:
        """Get the provider for the specified model."""
        # Simple mapping of model names to providers
        model_to_provider = {"gpt-": "openai", "claude-": "anthropic", "llama-": "local"}

        for prefix, provider_name in model_to_provider.items():
            if model_name.startswith(prefix):
                return self.model_providers.get(provider_name)

        return None

    async def generate_text(
        self,
        model: str,
        prompt: str,
        parameters: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AIResponse:
        """
        Generate text using an AI model with encrypted prompts and responses.

        Args:
            model: The AI model to use (e.g., 'gpt-4', 'claude-3-opus')
            prompt: The prompt to send to the AI model
            parameters: Optional parameters for the AI model
            metadata: Optional metadata for the request

        Returns:
            AIResponse containing the encrypted response

        Raises:
            ValueError: If the model is not available or if there's an error
        """
        if model not in self.available_models:
            raise ValueError(f"Model not available: {model}")

        # Log the request
        request_id = f"ai_req_{int(datetime.utcnow().timestamp() * 1000)}"
        self.security_manager.log_security_event(
            "ai_request",
            {
                "request_id": request_id,
                "model": model,
                "prompt_length": len(prompt),
                "timestamp": datetime.utcnow().isoformat(),
            },
        )

        try:
            # Encrypt the prompt
            encryption_result = self.crypto.encrypt(prompt.encode("utf-8"))

            # Create the request
            request = AIRequest(
                request_id=request_id,
                model=model,
                encrypted_prompt=encryption_result.ciphertext,
                parameters=parameters or {},
                metadata=metadata or {},
            )

            # Process the request
            response = await self._process_ai_request(request)

            # Log the successful response
            self.security_manager.log_security_event(
                "ai_response",
                {
                    "request_id": request_id,
                    "model": model,
                    "response_length": len(response.encrypted_response),
                    "timestamp": datetime.utcnow().isoformat(),
                },
            )

            return response

        except Exception as e:
            # Log the error
            self.security_manager.log_security_event(
                "ai_error",
                {
                    "request_id": request_id,
                    "model": model,
                    "error": str(e),
                    "timestamp": datetime.utcnow().isoformat(),
                },
            )
            raise

    async def _process_ai_request(self, request: AIRequest) -> AIResponse:
        """Process an AI request and return the response."""
        try:
            # Get the model provider
            provider = self._get_model_provider(request.model)
            if not provider:
                raise ValueError(f"No provider available for model: {request.model}")

            # Decrypt the prompt
            decryption_result = EncryptionResult(
                ciphertext=request.encrypted_prompt,
                iv=None,  # Will use the default IV from the crypto service
                tag=None,  # Will use the default tag from the crypto service
                key_id=None,  # Will use the current key
            )

            prompt = self.crypto.decrypt(decryption_result).decode("utf-8")

            # Call the appropriate provider
            if hasattr(provider, "generate_text"):
                response_text = await provider.generate_text(
                    model=request.model, prompt=prompt, parameters=request.parameters
                )

                # Encrypt the response
                encryption_result = self.crypto.encrypt(response_text.encode("utf-8"))

                # Create and return the response
                return AIResponse(
                    request_id=request.request_id,
                    model=request.model,
                    encrypted_response=encryption_result.ciphertext,
                    metadata={
                        "provider": provider.__class__.__name__,
                        "model": request.model,
                        "prompt_tokens": len(prompt.split()),
                        "response_tokens": len(response_text.split()),
                    },
                )
            else:
                raise ValueError(
                    f"Provider {provider.__class__.__name__} does not support text generation"
                )

        except Exception as e:
            logger.error(f"Error processing AI request: {e}", exc_info=True)
            raise

    async def decrypt_ai_response(self, response: Union[AIResponse, Dict[str, Any]]) -> str:
        """
        Decrypt an AI response.

        Args:
            response: The AI response to decrypt

        Returns:
            The decrypted response text
        """
        if isinstance(response, dict):
            response = AIResponse.from_dict(response)

        try:
            # Decrypt the response
            decryption_result = EncryptionResult(
                ciphertext=response.encrypted_response,
                iv=None,  # Will use the default IV from the crypto service
                tag=None,  # Will use the default tag from the crypto service
                key_id=None,  # Will use the current key
            )

            return self.crypto.decrypt(decryption_result).decode("utf-8")

        except Exception as e:
            logger.error(f"Failed to decrypt AI response: {e}", exc_info=True)
            raise ValueError("Failed to decrypt AI response") from e

    async def stream_text(
        self,
        model: str,
        prompt: str,
        parameters: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """
        Stream text from an AI model with encrypted prompts and responses.

        Args:
            model: The AI model to use
            prompt: The prompt to send to the AI model
            parameters: Optional parameters for the AI model
            metadata: Optional metadata for the request

        Yields:
            Encrypted chunks of the AI response
        """
        if model not in self.available_models:
            raise ValueError(f"Model not available: {model}")

        if not self.available_models[model].get("supports_streaming", False):
            raise ValueError(f"Model {model} does not support streaming")

        # Log the request
        request_id = f"ai_stream_{int(datetime.utcnow().timestamp() * 1000)}"
        self.security_manager.log_security_event(
            "ai_stream_start",
            {
                "request_id": request_id,
                "model": model,
                "prompt_length": len(prompt),
                "timestamp": datetime.utcnow().isoformat(),
            },
        )

        try:
            # Encrypt the prompt
            encryption_result = self.crypto.encrypt(prompt.encode("utf-8"))

            # Get the model provider
            provider = self._get_model_provider(model)
            if not provider:
                raise ValueError(f"No provider available for model: {model}")

            # Check if the provider supports streaming
            if not hasattr(provider, "stream_text"):
                raise ValueError(
                    f"Provider {provider.__class__.__name__} does not support streaming"
                )

            # Create a buffer to accumulate the response
            response_buffer = []

            # Stream the response from the provider
            async for chunk in provider.stream_text(
                model=model, prompt=prompt, parameters=parameters or {}
            ):
                # Encrypt the chunk
                chunk_encrypted = self.crypto.encrypt(chunk.encode("utf-8"))

                # Add to buffer
                response_buffer.append(chunk_encrypted.ciphertext)

                # Yield the encrypted chunk
                yield {
                    "request_id": request_id,
                    "chunk": chunk_encrypted.ciphertext.hex(),
                    "is_complete": False,
                }

            # Log the completion
            self.security_manager.log_security_event(
                "ai_stream_complete",
                {
                    "request_id": request_id,
                    "model": model,
                    "response_chunks": len(response_buffer),
                    "timestamp": datetime.utcnow().isoformat(),
                },
            )

            # Yield the completion marker
            yield {
                "request_id": request_id,
                "chunk": b"".hex(),
                "is_complete": True,
                "metadata": {
                    "model": model,
                    "chunks": len(response_buffer),
                    "provider": provider.__class__.__name__,
                },
            }

        except Exception as e:
            # Log the error
            self.security_manager.log_security_event(
                "ai_stream_error",
                {
                    "request_id": request_id,
                    "model": model,
                    "error": str(e),
                    "timestamp": datetime.utcnow().isoformat(),
                },
            )
            raise

    def get_usage_metrics(self) -> Dict[str, Any]:
        """
        Get usage metrics for the AI service.

        Returns:
            Dict containing usage metrics
        """
        # In a real implementation, this would track actual usage
        return {
            "total_requests": 0,
            "total_tokens": 0,
            "models_used": {},
            "last_updated": datetime.utcnow().isoformat(),
        }


# Create a default instance for easy import
secure_ai_service = SecureAIService()
