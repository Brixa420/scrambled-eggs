"""
LLM Service for handling local model interactions using Ollama.
"""

import asyncio
import hashlib
import json
import logging
import os
import time
from datetime import datetime
from typing import Any, AsyncGenerator, Dict, Optional, Union

import aiohttp

logger = logging.getLogger(__name__)


class LLMService:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(LLMService, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, base_url: str = "http://localhost:11434"):
        if self._initialized:
            return

        self.base_url = os.getenv("OLLAMA_BASE_URL", base_url).rstrip("/")
        self.model = os.getenv("LLM_MODEL", "llama3")
        self.timeout = int(os.getenv("LLM_TIMEOUT", "30"))  # seconds
        self.max_retries = int(os.getenv("LLM_MAX_RETRIES", "3"))
        self.rate_limit = int(os.getenv("LLM_RATE_LIMIT", "10"))  # requests per minute
        self.last_request_time = datetime.min
        self._initialized = True
        self._session = None
        self._loop = None
        self._cache = {}
        self._max_cache_size = 100
        logger.info(f"Initialized LLMService with model: {self.model}")

    async def _ensure_session(self):
        """Ensure we have a valid aiohttp session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()

    async def initialize(self):
        """Initialize the service and test the connection."""
        await self._ensure_session()
        await self._test_connection()

    async def _test_connection(self) -> bool:
        """Test connection to the LLM server."""
        try:
            # Log the connection attempt
            logger.info(f"🔍 Attempting to connect to LLM server at {self.base_url}")

            # Ensure we have a session
            await self._ensure_session()

            # Test with a simple GET request to /api/tags
            start_time = time.time()
            url = f"{self.base_url}/api/tags"
            logger.debug(f"Making request to: {url}")

            async with self._session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                response_time = (time.time() - start_time) * 1000  # Convert to ms
                response_text = await response.text()

                logger.debug(f"Response status: {response.status}")
                logger.debug(f"Response headers: {dict(response.headers)}")
                logger.debug(
                    f"Response body: {response_text[:500]}..."
                    if len(response_text) > 500
                    else f"Response body: {response_text}"
                )

                if response.status == 200:
                    try:
                        data = await response.json()
                        model_count = len(data.get("models", []))
                        logger.info(
                            f"✅ Successfully connected to LLM server in {response_time:.2f}ms. "
                            f"Found {model_count} available models."
                        )
                        if model_count > 0:
                            model_names = [m.get("name", "unknown") for m in data.get("models", [])]
                            logger.info(f"Available models: {', '.join(model_names)}")
                        return True
                    except Exception as e:
                        logger.error(f"❌ Failed to parse LLM server response: {str(e)}")
                        logger.debug(f"Raw response: {response_text}")
                        return False
                else:
                    logger.error(
                        f"❌ LLM server returned status {response.status}: {response.reason}\n"
                        f"Response: {response_text}"
                    )
                    return False

        except asyncio.TimeoutError:
            logger.error("⏱️  Connection to LLM server timed out after 5 seconds")
            return False

        except aiohttp.ClientError as e:
            logger.error(f"🔌 Failed to connect to LLM server: {str(e)}")
            if "Cannot connect to host" in str(e):
                logger.info("💡 Make sure Ollama is running. You can start it with: ollama serve")
            return False

        except Exception as e:
            logger.error(f"⚠️  Unexpected error connecting to LLM server: {str(e)}", exc_info=True)
            return False

    async def _enforce_rate_limit(self):
        """Enforce rate limiting between requests."""
        await self._ensure_session()
        now = datetime.now()
        time_since_last = (now - self.last_request_time).total_seconds()
        min_interval = 60 / self.rate_limit  # Convert RPS to interval in seconds

        if time_since_last < min_interval:
            sleep_time = min_interval - time_since_last
            logger.debug(f"Rate limiting: sleeping for {sleep_time:.2f}s")
            await asyncio.sleep(sleep_time)

        self.last_request_time = datetime.now()

    def _generate_cache_key(self, prompt: str, **kwargs) -> str:
        """Generate a cache key for the given prompt and parameters."""
        key_dict = {"prompt": prompt, **kwargs}
        key_str = json.dumps(key_dict, sort_keys=True)
        return hashlib.md5(key_str.encode()).hexdigest()

    async def close(self):
        """Close the aiohttp session."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None
            logger.info("Closed LLM service session")

    async def _cached_generate(self, cache_key: str, prompt: str, **kwargs) -> tuple:
        """
        Internal method with caching implementation.

        Args:
            cache_key: The cache key for the request
            prompt: The prompt to generate a response for
            **kwargs: Additional parameters for the model

        Returns:
            tuple: (response, metadata) from the LLM API
        """
        if not hasattr(self, "_cache"):
            self._cache = {}
            self._max_cache_size = 100

        if cache_key in self._cache:
            logger.debug(f"Cache hit for key: {cache_key}")
            return self._cache[cache_key]

        # If cache is full, remove the oldest item
        if len(self._cache) >= self._max_cache_size:
            oldest_key = next(iter(self._cache))
            del self._cache[oldest_key]
            logger.debug(f"Cache full, removed oldest key: {oldest_key}")

        # Generate and cache the response
        logger.debug(f"Cache miss for key: {cache_key}, generating new response")
        response = await self._call_llm_api(prompt, **kwargs)
        self._cache[cache_key] = response
        return response

    async def _stream_response(self, prompt: str, **kwargs) -> AsyncGenerator[Dict[str, Any], None]:
        """Stream the response from the LLM."""
        await self._ensure_session()
        url = f"{self.base_url}/api/generate"
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": True,
            **{k: v for k, v in kwargs.items() if v is not None},
        }

        last_error = None
        try:
            await self._enforce_rate_limit()

            async with self._session.post(
                url, json=payload, timeout=aiohttp.ClientTimeout(total=self.timeout)
            ) as response:
                response.raise_for_status()

                buffer = ""
                async for line in response.content:
                    if line:
                        try:
                            chunk = json.loads(line.decode("utf-8").strip())
                            if "response" in chunk:
                                buffer += chunk["response"]
                                yield {
                                    "chunk": chunk["response"],
                                    "done": chunk.get("done", False),
                                    "context": chunk.get("context"),
                                    "model": chunk.get("model"),
                                }
                            if chunk.get("done", False):
                                break
                        except json.JSONDecodeError as e:
                            logger.warning(f"Failed to parse LLM response: {e}")
                            continue

                # Final yield with the complete response
                yield {"response": buffer, "done": True, "context": None, "model": self.model}

        except Exception as e:
            last_error = e
            logger.error(f"Error in _stream_response: {e}")
            yield {"chunk": "", "done": True, "error": str(e)}

    async def _call_llm_api(self, prompt: str, **kwargs) -> Dict[str, Any]:
        """Make a single API call to the LLM."""
        await self._ensure_session()
        url = f"{self.base_url}/api/generate"
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            **{k: v for k, v in kwargs.items() if v is not None},
        }

        last_error = None
        for attempt in range(self.max_retries):
            try:
                await self._enforce_rate_limit()
                start_time = time.time()

                async with self._session.post(
                    url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as response:
                    response.raise_for_status()

                    response_time = time.time() - start_time
                    logger.info(f"LLM API call completed in {response_time:.2f}s")

                    result = await response.json()
                    return result.get("response", ""), {
                        "model": result.get("model"),
                        "total_duration": result.get("total_duration"),
                        "load_duration": result.get("load_duration"),
                        "prompt_eval_count": result.get("prompt_eval_count"),
                        "eval_count": result.get("eval_count"),
                        "eval_duration": result.get("eval_duration"),
                    }

            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                last_error = e
                wait_time = 2**attempt  # Exponential backoff
                logger.warning(f"Attempt {attempt + 1} failed: {e}. Retrying in {wait_time}s...")
                await asyncio.sleep(wait_time)
            except Exception as e:
                last_error = e
                logger.error(f"Unexpected error in API call: {e}")
                break

        logger.error(f"All {self.max_retries} attempts failed. Last error: {last_error}")
        return None, {"error": str(last_error) if last_error else "Unknown error"}

    async def generate_response(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        use_cache: bool = True,
        stream: bool = False,
        **kwargs,
    ) -> Union[str, AsyncGenerator[Dict[str, Any], None]]:
        """
        Generate a response from the LLM with enhanced error handling and caching.

        Args:
            prompt: The user's input prompt
            system_prompt: Optional system message to guide the model
            use_cache: Whether to use response caching
            stream: Whether to stream the response
            **kwargs: Additional parameters for the model

        Returns:
            If stream=True: Async generator yielding response chunks
            If stream=False: Generated response as a string, or error message if generation fails
        """
        try:
            # Prepare parameters
            params = {k: v for k, v in {"system": system_prompt, **kwargs}.items() if v is not None}

            # For streaming, don't use cache
            if stream:
                return self._stream_response(prompt, **params)

            # Generate cache key if caching is enabled
            cache_key = self._generate_cache_key(prompt, **params) if use_cache else None

            # Get response from cache or generate new
            if use_cache and cache_key:
                try:
                    response, _ = self._cached_generate(cache_key, prompt, **params)
                    logger.info("Serving response from cache")
                    return response or "I couldn't generate a response. Please try again."
                except Exception as e:
                    logger.warning(f"Cache lookup failed: {e}")

            # Generate new response
            response, metadata = await self._call_llm_api(prompt, **params)

            if response is None:
                logger.error(f"Failed to generate response. Metadata: {metadata}")
                return "I'm having trouble generating a response right now. Please try again later."

            # Log performance metrics
            if metadata and not metadata.get("error"):
                logger.info(
                    f"Generated response in {metadata.get('total_duration', 0)/1e9:.2f}s "
                    f"(eval: {metadata.get('eval_count')} tokens, "
                    f"prompt: {metadata.get('prompt_eval_count')} tokens)"
                )

            return response

        except Exception as e:
            logger.exception("Unexpected error in generate_response")
            if stream:

                async def error_generator():
                    yield {
                        "chunk": "An unexpected error occurred. Please try again later.",
                        "done": True,
                        "error": str(e),
                    }

                return error_generator()
            return "An unexpected error occurred. Please try again later."

    async def get_model_info(self) -> Optional[Dict[str, Any]]:
        """
        Get information about the current model.

        Returns:
            Optional[Dict[str, Any]]: Model information if successful, None otherwise
        """
        try:
            await self._ensure_session()
            url = f"{self.base_url}/api/tags"
            logger.debug(f"Fetching model info from: {url}")

            async with self._session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                response.raise_for_status()
                data = await response.json()

                if not isinstance(data, dict):
                    logger.error(f"Unexpected response format: {data}")
                    return None

                models = data.get("models", [])
                if not models:
                    logger.warning("No models found in the response")
                    return None

                logger.debug(f"Found {len(models)} models in the response")

                # Try to find the current model
                for model in models:
                    if not isinstance(model, dict):
                        logger.warning(f"Unexpected model format: {model}")
                        continue

                    model_name = model.get("name")
                    if model_name == self.model:
                        logger.info(f"Found matching model: {model_name}")
                        return model

                # If we get here, the model wasn't found
                available_models = [m.get("name", "unknown") for m in models]
                logger.warning(
                    f"Model '{self.model}' not found. Available models: {', '.join(available_models)}"
                )
                return models[0]  # Return the first available model as fallback

        except asyncio.TimeoutError:
            logger.error("Request to get model info timed out after 10 seconds")
            return None

        except aiohttp.ClientError as e:
            logger.error(f"Failed to get model info: {str(e)}")
            return None

        except Exception as e:
            logger.error(f"Unexpected error getting model info: {str(e)}", exc_info=True)
            return None


async def main():
    """
        Example usage of the LLMService.
    {{ ... }}
        This function demonstrates:
        1. Connecting to the LLM server
        2. Getting model information
        3. Sending a non-streaming request
        4. Sending a streaming request
        5. Testing response caching
    """
    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler(), logging.FileHandler("llm_service.log")],
    )
    logger = logging.getLogger(__name__)

    logger.info("=" * 80)
    logger.info("STARTING LLM SERVICE EXAMPLE")
    logger.info("=" * 80)

    llm = LLMService()

    try:
        # Test connection and model info
        logger.info("\n[1/4] Testing connection and getting model info...")
        model_info = await llm.get_model_info()
        if model_info:
            logger.info(f"✅ Model info: {json.dumps(model_info, indent=2)}")
        else:
            logger.error("❌ Failed to get model info")
            return

        # Test non-streaming response
        logger.info("\n[2/4] Testing non-streaming response...")
        try:
            response = await llm.generate_response(
                "Tell me a short joke about AI",
                system_prompt="You are a helpful AI assistant.",
                temperature=0.7,
                max_tokens=100,
                stream=False,
            )
            logger.info(f"✅ Response: {response}")
        except Exception as e:
            logger.error(f"❌ Non-streaming request failed: {e}", exc_info=True)
            return

        # Test streaming response
        logger.info("\n[3/4] Testing streaming response...")
        try:
            response_gen = await llm.generate_response(
                "Explain quantum computing in simple terms",
                system_prompt="You are a helpful AI assistant.",
                temperature=0.7,
                max_tokens=200,
                stream=True,
            )

            full_response = ""
            logger.info("Streaming response (chunks marked with '|'):")

            async for chunk in response_gen:
                if chunk.get("chunk"):
                    print("|", end="", flush=True)
                    full_response += chunk["chunk"]
                if chunk.get("done"):
                    if "error" in chunk:
                        logger.error(f"\n❌ Error in streaming response: {chunk['error']}")
                    else:
                        logger.info(
                            f"\n✅ Streaming complete. Response length: {len(full_response)} characters"
                        )
        except Exception as e:
            logger.error(f"❌ Streaming request failed: {e}", exc_info=True)
            return

        # Test response caching
        logger.info("\n[4/4] Testing response caching...")
        try:
            test_prompt = "What's the capital of France?"

            # First request (not cached)
            start_time = time.time()
            response1 = await llm.generate_response(test_prompt, stream=False)
            first_request_time = time.time() - start_time
            logger.info(f"First request took {first_request_time:.2f}s")

            # Second request (should be cached)
            start_time = time.time()
            response2 = await llm.generate_response(test_prompt, stream=False)
            second_request_time = time.time() - start_time
            logger.info(f"Second request took {second_request_time:.2f}s")

            if response1 == response2:
                logger.info(
                    f"✅ Caching works! Second request was {first_request_time/max(0.01, second_request_time):.1f}x faster"
                )
            else:
                logger.warning("⚠️  Caching may not be working as expected")

        except Exception as e:
            logger.error(f"❌ Cache test failed: {e}", exc_info=True)

    except Exception as e:
        logger.error(f"❌ Unexpected error in main: {e}", exc_info=True)

    finally:
        # Clean up resources
        try:
            await llm.close()
            logger.info("✅ Cleaned up resources")
        except Exception as e:
            logger.error(f"❌ Error during cleanup: {e}", exc_info=True)

    logger.info("\n" + "=" * 80)
    logger.info("LLM SERVICE EXAMPLE COMPLETE")
    logger.info("=" * 80)


if __name__ == "__main__":
    asyncio.run(main())
