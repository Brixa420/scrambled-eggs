"""
LLM Service for handling local model interactions using Ollama.
"""

import asyncio
import hashlib
import json
import logging
import os
import time
import numpy as np
from datetime import datetime, timedelta
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

import aiohttp

logger = logging.getLogger(__name__)


class ModelQuantization(str, Enum):
    NONE = "none"
    Q4_0 = "q4_0"
    Q5_0 = "q5_0"
    Q8_0 = "q8_0"
    F16 = "f16"

@dataclass
class CacheEntry:
    response: str
    metadata: Dict[str, Any]
    created_at: datetime = field(default_factory=datetime.now)
    last_accessed: datetime = field(default_factory=datetime.now)
    access_count: int = 1
    embedding: Optional[np.ndarray] = None

class LLMService:
    _instance = None
    _semantic_model = None  # For semantic caching

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(LLMService, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, base_url: str = "http://localhost:11434"):
        if self._initialized:
            return

        self.base_url = os.getenv("OLLAMA_BASE_URL", base_url).rstrip("/")
        self.model = os.getenv("LLM_MODEL", "llama3:8b-instruct-q4_0")
        self.timeout = int(os.getenv("LLM_TIMEOUT", "60"))  # Increased timeout
        self.max_retries = int(os.getenv("LLM_MAX_RETRIES", "3"))
        self.rate_limit = int(os.getenv("LLM_RATE_LIMIT", "30"))  # Increased rate limit
        self.last_request_time = datetime.min
        self._initialized = True
        self._session = None
        self._loop = asyncio.get_event_loop()
        self._cache: Dict[str, CacheEntry] = {}
        self._max_cache_size = int(os.getenv("LLM_CACHE_SIZE", "100"))
        self._cache_ttl = int(os.getenv("LLM_CACHE_TTL", str(24 * 60 * 60)))  # 24h default TTL
        
        # Performance metrics
        self.metrics = {
            "total_requests": 0,
            "total_tokens": 0,
            "total_time": 0.0,
            "cache_hits": 0,
            "cache_misses": 0,
            "semantic_cache_hits": 0,
            "batch_requests_processed": 0,
            "avg_batch_size": 0.0,
        }
        
        # Default optimized parameters
        self.default_params = {
            "temperature": float(os.getenv("LLM_TEMPERATURE", "0.7")),
            "top_p": float(os.getenv("LLM_TOP_P", "0.9")),
            "top_k": int(os.getenv("LLM_TOP_K", "40")),
            "repeat_penalty": float(os.getenv("LLM_REPEAT_PENALTY", "1.1")),
            "num_ctx": int(os.getenv("LLM_NUM_CTX", "2048")),
            "num_thread": max(1, os.cpu_count() // 2),  # Use half the available cores
            "num_gpu": 1 if os.getenv("CUDA_VISIBLE_DEVICES") else 0,
            "num_gqa": int(os.getenv("LLM_NUM_GQA", "8")),
            "num_gpu_layers": int(os.getenv("LLM_NUM_GPU_LAYERS", "20")),
        }
        
        logger.info(f"Initialized LLMService with model: {self.model}")
        logger.info(f"Using optimized parameters: {json.dumps(self.default_params, indent=2)}")
        
        # Start performance monitoring
        self._monitor_task = self._loop.create_task(self.log_performance())

    async def _ensure_session(self):
        """Ensure we have a valid aiohttp session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()

    async def initialize(self):
        """Initialize the service and test the connection."""
        await self._ensure_session()
        await self._test_connection()

    async def get_metrics(self) -> dict:
        """Get performance metrics."""
        total_requests = self.metrics["total_requests"]
        total_time = self.metrics["total_time"]
        
        return {
            **self.metrics,
            "avg_time_per_request": total_time / total_requests if total_requests > 0 else 0,
            "tokens_per_second": (self.metrics["total_tokens"] / total_time) if total_time > 0 else 0,
            "cache_hit_rate": (
                self.metrics["cache_hits"] / 
                (self.metrics["cache_hits"] + self.metrics["cache_misses"])
                if (self.metrics["cache_hits"] + self.metrics["cache_misses"]) > 0 
                else 0
            ),
        }

    async def log_performance(self):
        """Log performance metrics periodically."""
        while True:
            try:
                metrics = await self.get_metrics()
                logger.info(
                    f"📊 LLM Performance - "
                    f"Requests: {metrics['total_requests']}, "
                    f"Avg: {metrics['avg_time_per_request']:.2f}s, "
                    f"Tokens/s: {metrics['tokens_per_second']:.1f}, "
                    f"Cache: {metrics['cache_hit_rate']:.1%} "
                    f"({metrics['cache_hits']}/{metrics['cache_hits'] + metrics['cache_misses']})"
                )
            except Exception as e:
                logger.error(f"Error logging performance metrics: {e}")
            
            await asyncio.sleep(300)  # Log every 5 minutes

    def get_optimized_params(self, prompt_length: int) -> dict:
        """Get optimized parameters based on prompt length."""
        params = self.default_params.copy()
        
        # Adjust based on prompt length
        if prompt_length > 1000:
            params["num_ctx"] = min(4096, prompt_length + 512)
            params["num_thread"] = max(4, os.cpu_count() // 2)
        
        return params

    async def preload_common_prompts(self):
        """Preload common prompts to warm up the model."""
        common_prompts = [
            "Hello, how are you?",
            "What can you do?",
            "Tell me about yourself",
        ]
        try:
            await self.batch_generate(common_prompts)
            logger.info("Successfully preloaded common prompts")
        except Exception as e:
            logger.warning(f"Failed to preload common prompts: {e}")

    async def batch_generate(self, prompts: list[str], **kwargs) -> list[str]:
        """Process multiple prompts in a single batch."""
        return await asyncio.gather(
            *(self.generate_response(prompt, **kwargs) for prompt in prompts)
        )

    async def _preprocess_prompt(self, prompt: str) -> str:
        """Preprocess the prompt for better performance."""
        # Remove extra whitespace
        prompt = " ".join(prompt.split())
        # Add common system prompt if needed
        if not prompt.startswith("### System:"):
            prompt = "### System: You are a helpful AI assistant.\n\n### User: " + prompt
        return prompt

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

    async def _enforce_rate_limit(self, priority: int = 1):
        """
        Enforce rate limiting between requests with priority support.
        
        Args:
            priority: Request priority (1-10, higher is more important)
        """
        await self._ensure_session()
        now = datetime.now()
        time_since_last = (now - self.last_request_time).total_seconds()
        
        # Adjust rate limit based on priority (higher priority = shorter delay)
        priority_factor = 1.1 - (priority / 20)  # 0.6x to 1.0x delay for priority 1-10
        min_interval = (60 / self.rate_limit) * priority_factor
        
        if time_since_last < min_interval:
            sleep_time = min_interval - time_since_last
            logger.debug(f"Rate limiting: sleeping for {sleep_time:.2f}s (priority: {priority})")
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

    async def _get_semantic_embedding(self, text: str) -> np.ndarray:
        """Generate a semantic embedding for the given text."""
        if self._semantic_model is None:
            try:
                self._semantic_model = SentenceTransformer('all-MiniLM-L6-v2')
            except Exception as e:
                logger.warning(f"Failed to load semantic model: {e}")
                return None
        
        try:
            return self._semantic_model.encode(text, convert_to_numpy=True)
        except Exception as e:
            logger.warning(f"Error generating semantic embedding: {e}")
            return None

    def _find_semantic_match(self, prompt_embedding: np.ndarray, threshold: float = 0.9) -> Optional[Tuple[str, CacheEntry]]:
        """Find a semantically similar cached response."""
        if prompt_embedding is None:
            return None
            
        best_match = None
        best_score = threshold
        
        for cache_key, entry in self._cache.items():
            if entry.embedding is not None:
                similarity = cosine_similarity(
                    [prompt_embedding], 
                    [entry.embedding]
                )[0][0]
                
                if similarity > best_score:
                    best_score = similarity
                    best_match = (cache_key, entry)
        
        if best_match:
            logger.debug(f"Semantic cache hit with similarity score: {best_score:.2f}")
            self.metrics["semantic_cache_hits"] += 1
            return best_match
            
        return None

    async def _cleanup_cache(self):
        """Clean up expired and least recently used cache entries."""
        now = datetime.now()
        expired_keys = [
            key for key, entry in self._cache.items()
            if (now - entry.last_accessed).total_seconds() > self._cache_ttl
        ]
        
        for key in expired_keys:
            del self._cache[key]
            
        # If still over max size, remove least recently used
        if len(self._cache) > self._max_cache_size:
            lru_key = min(
                self._cache.items(),
                key=lambda item: (item[1].last_accessed, -item[1].access_count)
            )[0]
            del self._cache[lru_key]

    async def _cached_generate(
        self, 
        cache_key: str, 
        prompt: str, 
        use_semantic_cache: bool = True,
        **kwargs
    ) -> Tuple[Optional[str], Dict[str, Any]]:
        """
        Enhanced caching implementation with semantic caching.

        Args:
            cache_key: The cache key for the request
            prompt: The prompt to generate a response for
            use_semantic_cache: Whether to use semantic caching
            **kwargs: Additional parameters for the model

        Returns:
            tuple: (response, metadata) from the LLM API or cache
        """
        # Clean up expired cache entries
        await self._cleanup_cache()
        
        # Check exact match first
        if cache_key in self._cache:
            entry = self._cache[cache_key]
            entry.last_accessed = datetime.now()
            entry.access_count += 1
            logger.debug(f"Exact cache hit for key: {cache_key}")
            self.metrics["cache_hits"] += 1
            return entry.response, entry.metadata
        
        # Try semantic cache if enabled
        if use_semantic_cache:
            prompt_embedding = await self._get_semantic_embedding(prompt)
            semantic_match = self._find_semantic_match(prompt_embedding)
            
            if semantic_match:
                match_key, match_entry = semantic_match
                match_entry.last_accessed = datetime.now()
                match_entry.access_count += 1
                logger.debug(f"Semantic cache hit for key: {match_key}")
                return match_entry.response, match_entry.metadata
        
        # If cache is full, remove the least recently used item
        if len(self._cache) >= self._max_cache_size:
            lru_key = min(
                self._cache.items(),
                key=lambda item: (item[1].last_accessed, -item[1].access_count)
            )[0]
            logger.debug(f"Cache full, removing LRU key: {lru_key}")
            del self._cache[lru_key]
        
        # Generate and cache the response
        logger.debug(f"Cache miss for key: {cache_key}, generating new response")
        response, metadata = await self._call_llm_api(prompt, **kwargs)
        
        if response is not None:
            # Generate and store embedding for semantic caching
            embedding = await self._get_semantic_embedding(prompt) if use_semantic_cache else None
            self._cache[cache_key] = CacheEntry(
                response=response,
                metadata=metadata or {},
                embedding=embedding
            )
        
        return response, metadata or {}

    async def _stream_response(self, prompt: str, **kwargs) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Optimized streaming response handler with enhanced performance and error handling.
        
        Args:
            prompt: The prompt to generate a response for
            **kwargs: Additional parameters for the model
            
        Yields:
            Dict[str, Any]: Response chunks with metadata
        """
        start_time = time.time()
        response_buffer = []
        total_tokens = 0
        prompt_tokens = 0
        
        try:
            await self._ensure_session()
            url = f"{self.base_url}/api/generate"
            
            # Prepare the request data with optimized defaults
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": True,
                **{k: v for k, v in kwargs.items() if v is not None},
            }
            
            logger.debug(f"Starting streaming request to {url}")
            
            # Enforce rate limiting before starting the stream
            await self._enforce_rate_limit()
            
            async with self._session.post(
                url, 
                json=payload, 
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            ) as response:
                response.raise_for_status()
                
                buffer = ""
                async for line in response.content:
                    if not line.strip():
                        continue
                        
                    try:
                        # Parse the JSON response
                        chunk = json.loads(line.decode("utf-8").strip())
                        
                        # Skip empty responses
                        if not chunk:
                            continue
                            
                        # Add to response buffer for error recovery (keep last 10 chunks)
                        response_buffer.append(chunk)
                        if len(response_buffer) > 10:
                            response_buffer.pop(0)
                        
                        # Process the chunk
                        if "response" in chunk:
                            buffer += chunk["response"]
                            
                            # Yield the chunk immediately for streaming
                            yield {
                                "chunk": chunk["response"],
                                "done": False,
                                "context": chunk.get("context"),
                                "model": chunk.get("model", self.model),
                                "prompt_eval_count": chunk.get("prompt_eval_count", 0),
                                "eval_count": chunk.get("eval_count", 0),
                            }
                            
                            # Update token counts
                            if "eval_count" in chunk:
                                total_tokens = chunk["eval_count"]
                            if "prompt_eval_count" in chunk:
                                prompt_tokens = chunk["prompt_eval_count"]
                        
                        # Handle completion
                        if chunk.get("done", False):
                            duration = (time.time() - start_time) * 1000  # in ms
                            tokens_per_sec = (total_tokens / (duration / 1000)) if duration > 0 else 0
                            
                            logger.info(
                                f"Streaming completed in {duration:.2f}ms | "
                                f"Prompt: {prompt_tokens} tokens | "
                                f"Completion: {total_tokens} tokens | "
                                f"Speed: {tokens_per_sec:.1f} tokens/sec"
                            )
                            
                            # Update metrics
                            self.metrics["total_requests"] += 1
                            self.metrics["total_time"] += duration / 1000  # convert to seconds
                            self.metrics["total_tokens"] += total_tokens + prompt_tokens
                            
                            # Final yield with complete response
                            yield {
                                "response": buffer,
                                "done": True,
                                "context": chunk.get("context"),
                                "model": chunk.get("model", self.model),
                                "prompt_eval_count": prompt_tokens,
                                "eval_count": total_tokens,
                                "total_duration": duration,
                            }
                            break
                            
                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to parse JSON chunk: {line}. Error: {e}")
                        yield {
                            "chunk": "\n[Error: Invalid response format]",
                            "done": True,
                            "error": f"JSON decode error: {str(e)}",
                        }
                        break
                        
                    except Exception as e:
                        logger.exception(f"Error processing chunk: {e}")
                        yield {
                            "chunk": "\n[Error processing response]",
                            "done": True,
                            "error": str(e),
                        }
                        break
        
        except asyncio.CancelledError:
            logger.info("Streaming was cancelled by the client")
            yield {
                "chunk": "\n[Stream cancelled by user]",
                "done": True,
                "error": "cancelled",
            }
            
        except aiohttp.ClientError as e:
            logger.error(f"Network error during streaming: {e}")
            yield {
                "chunk": "\n[Network error during streaming]",
                "done": True,
                "error": str(e),
            }
            
        except Exception as e:
            logger.exception("Unexpected error in _stream_response")
            yield {
                "chunk": "\n[An unexpected error occurred]",
                "done": True,
                "error": str(e),
            }
            
        finally:
            # Log the end of the streaming session
            duration = (time.time() - start_time) * 1000  # in ms
            logger.info(f"Streaming session ended after {duration:.2f}ms")

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

    async def batch_generate(
        self, 
        prompts: List[str], 
        system_prompt: Optional[str] = None,
        use_cache: bool = True,
        **kwargs
    ) -> List[Union[str, Exception]]:
        """
        Process multiple prompts in a single batch for better throughput.
        
        Args:
            prompts: List of prompts to process
            system_prompt: Optional system message for all prompts
            use_cache: Whether to use caching
            **kwargs: Additional parameters for the model
            
        Returns:
            List of responses or exceptions
        """
        start_time = time.time()
        batch_size = len(prompts)
        logger.info(f"Processing batch of {batch_size} prompts")
        
        # Update metrics
        self.metrics["batch_requests_processed"] += batch_size
        self.metrics["avg_batch_size"] = (
            (self.metrics["avg_batch_size"] * (self.metrics["batch_requests_processed"] - batch_size) + batch_size) /
            self.metrics["batch_requests_processed"]
        )
        
        # Process each prompt in parallel
        tasks = [
            self.generate_response(
                prompt=prompt,
                system_prompt=system_prompt,
                use_cache=use_cache,
                stream=False,
                **kwargs
            )
            for prompt in prompts
        ]
        
        try:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            duration = (time.time() - start_time) * 1000  # in ms
            tokens_per_sec = (sum(len(str(r).split()) for r in results) / (duration / 1000)) if duration > 0 else 0
            
            logger.info(
                f"Processed batch of {batch_size} prompts in {duration:.2f}ms "
                f"({tokens_per_sec:.1f} tokens/sec)"
            )
            
            return results
            
        except Exception as e:
            logger.error(f"Error in batch processing: {e}")
            return [Exception(f"Batch processing failed: {e}")] * batch_size

    async def generate_response(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        use_cache: bool = True,
        use_semantic_cache: bool = True,
        stream: bool = False,
        priority: int = 1,
        **kwargs,
    ) -> Union[str, AsyncGenerator[Dict[str, Any], None]]:
        """
        Generate an optimized response from the LLM with enhanced performance.
        
        Args:
            prompt: The user's input prompt
            system_prompt: Optional system message to guide the model
            use_cache: Whether to use response caching (default: True)
            use_semantic_cache: Whether to use semantic caching (default: True)
            stream: Whether to stream the response (default: False)
            priority: Request priority (1-10, higher is more important)
            **kwargs: Additional parameters for the model
            
        Returns:
            If stream=True: Async generator yielding response chunks
            If stream=False: Generated response as a string, or error message if generation fails
        """
        start_time = time.time()
        
        try:
            # Preprocess the prompt for better performance
            prompt = await self._preprocess_prompt(prompt)
            
            # Get optimized parameters based on prompt length and priority
            optimized_params = self.get_optimized_params(len(prompt))
            
            # Adjust parameters based on priority (higher priority = higher quality, lower temp)
            priority = max(1, min(10, priority))  # Clamp to 1-10
            if priority > 5:  # High priority - higher quality
                optimized_params["temperature"] = max(0.1, optimized_params.get("temperature", 0.7) * (1.1 - (priority / 20)))
                optimized_params["top_p"] = min(1.0, optimized_params.get("top_p", 0.9) * (0.95 + (priority / 200)))
            
            # Merge parameters with optimized defaults (allow override)
            params = {
                **optimized_params,
                **{k: v for k, v in {"system": system_prompt, **kwargs}.items() if v is not None}
            }
            
            # For streaming responses
            if stream:
                return self._optimized_stream_response(prompt, **params)

            # Generate cache key if caching is enabled
            cache_key = self._generate_cache_key(prompt, **params) if use_cache else None

            # Check cache first if enabled
            if use_cache and cache_key:
                try:
                    response, metadata = await self._cached_generate(
                        cache_key=cache_key,
                        prompt=prompt,
                        use_semantic_cache=use_semantic_cache,
                        **params
                    )
                    
                    if response is not None:
                        duration = (time.time() - start_time) * 1000  # in ms
                        self.metrics["cache_hits"] += 1
                        logger.info(f"Served from cache in {duration:.2f}ms")
                        return response
                        
                except Exception as e:
                    logger.warning(f"Cache lookup failed: {e}")
            
            self.metrics["cache_misses"] += 1
            
            # Enforce rate limiting with priority
            await self._enforce_rate_limit(priority=priority)

            # Generate new response with retry logic
            last_error = None
            for attempt in range(self.max_retries):
                try:
                    response, metadata = await self._call_llm_api(prompt, **params)
                    
                    if response is None:
                        error_msg = f"Failed to generate response. Attempt {attempt + 1}/{self.max_retries}"
                        logger.error(f"{error_msg}. Metadata: {metadata}")
                        last_error = error_msg
                        continue
                        
                    # Update cache if enabled
                    if use_cache and cache_key:
                        prompt_embedding = await self._get_semantic_embedding(prompt) if use_semantic_cache else None
                        self._cache[cache_key] = CacheEntry(
                            response=response,
                            metadata={
                                "cached_at": datetime.now().isoformat(),
                                **metadata
                            },
                            embedding=prompt_embedding
                        )
                    
                    # Update metrics
                    duration = (time.time() - start_time) * 1000  # in ms
                    self.metrics["total_requests"] += 1
                    self.metrics["total_time"] += duration / 1000  # convert to seconds
                    self.metrics["total_tokens"] += metadata.get("eval_count", len(response.split()))
                    
                    # Log performance
                    if metadata and not metadata.get("error"):
                        logger.info(
                            f"Generated response in {duration:.2f}ms "
                            f"(eval: {metadata.get('eval_count', 0)} tokens, "
                            f"prompt: {metadata.get('prompt_eval_count', 0)} tokens, "
                            f"priority: {priority})"
                        )
                    
                    return response
                    
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    last_error = e
                    # Add jitter to avoid thundering herd
                    jitter = random.uniform(0.1, 0.5)
                    backoff = min((2 ** attempt) + jitter, 30)  # Max 30s backoff
                    logger.warning(
                        f"Attempt {attempt + 1}/{self.max_retries} failed. "
                        f"Retrying in {backoff:.1f}s... Error: {e}"
                    )
                    await asyncio.sleep(backoff)
            
            # If we get here, all retries failed
            error_msg = f"Failed after {self.max_retries} attempts. Last error: {last_error}"
            logger.error(error_msg)
            return f"Error: {error_msg}"

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
