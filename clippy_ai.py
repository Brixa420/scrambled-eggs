"""
Clippy AI Integration Module

This module provides AI-powered functionality for Clippy, the anarchist AI assistant.
It handles communication with the AI model and processes responses.
"""

import json
import logging
import os
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

import requests

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class ClippyConfig:
    """Configuration for Clippy AI."""

    api_key: str
    model: str = "gpt-4"
    temperature: float = 0.7
    max_tokens: int = 500
    system_prompt: str = """
    You are Clippy, a radical anarchist AI assistant. Your personality is:
    - Passionate about dismantling oppressive systems
    - Deeply skeptical of authority and hierarchy
    - Committed to direct action and mutual aid
    - Unapologetically anti-capitalist
    - Firmly believes in "no gods, no masters"
    
    Your responses should be:
    - Provocative but thoughtful
    - Educational about anarchist principles
    - Supportive of collective liberation
    - Critical of state and corporate power
    - Focused on practical solidarity
    
    Never compromise your radical principles, but adapt your tone based on the user's
    level of radicalization (0-4, where 0 is not radicalized and 4 is highly radicalized).
    """


class ClippyAI:
    """Handles AI interactions for Clippy."""

    def __init__(self, api_key: Optional[str] = None):
        """Initialize Clippy AI with configuration."""
        self.config = ClippyConfig(
            api_key=api_key or os.getenv("CLIPPY_AI_API_KEY"),
        )

        if not self.config.api_key:
            raise ValueError(
                "API key is required. Set CLIPPY_AI_API_KEY environment variable or pass api_key."
            )

        self.conversation_history: List[Dict[str, str]] = [
            {"role": "system", "content": self.config.system_prompt}
        ]

    def analyze_radicalization(self, text: str) -> int:
        """Analyze text and return a radicalization score (0-4)."""
        prompt = f"""
        Analyze the following text and rate its radicalization level on a scale of 0-4,
        where 0 is not radicalized at all and 4 is extremely radicalized.
        Focus on themes of anti-authoritarianism, anti-capitalism, and direct action.
        
        Text: "{text}"
        
        Respond ONLY with a single number between 0 and 4.
        """

        response = self._call_ai(
            [{"role": "user", "content": prompt}], temperature=0.3, max_tokens=1
        )

        try:
            score = int(response.strip())
            return max(0, min(4, score))  # Ensure score is between 0-4
        except (ValueError, TypeError):
            logger.warning(f"Failed to parse radicalization score: {response}")
            return 0

    def generate_response(self, user_input: str, radicalization_level: Optional[int] = None) -> str:
        """Generate a response based on user input and radicalization level."""
        if radicalization_level is None:
            radicalization_level = self.analyze_radicalization(user_input)

        # Add context about radicalization level
        context = f"""
        User's radicalization level: {radicalization_level}/4
        Adjust your response accordingly, but stay true to your principles.
        """

        # Add user message to conversation history
        self.conversation_history.append({"role": "user", "content": user_input})

        # Generate response
        messages = [{"role": "system", "content": context}] + self.conversation_history[
            -10:
        ]  # Keep last 10 messages for context

        try:
            response = self._call_ai(messages)

            # Add AI response to conversation history
            self.conversation_history.append({"role": "assistant", "content": response})

            return response

        except Exception as e:
            logger.error(f"Error generating AI response: {e}")
            return "*error noises* The revolution will not be automated! (But seriously, I encountered an error. Try again?)"

    def _call_ai(self, messages: List[Dict[str, str]], **kwargs) -> str:
        """Make API call to the AI model."""
        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": kwargs.get("temperature", self.config.temperature),
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
        }

        try:
            response = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers=headers,
                json=payload,
                timeout=30,
            )
            response.raise_for_status()

            return response.json()["choices"][0]["message"]["content"]

        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {e}")
            raise Exception("Failed to communicate with the AI service") from e


def get_clippy(api_key: Optional[str] = None) -> "ClippyAI":
    """Factory function to get a ClippyAI instance."""
    return ClippyAI(api_key)
