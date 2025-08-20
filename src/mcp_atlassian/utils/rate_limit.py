"""Rate limiting utilities for MCP Atlassian.

This module provides rate limiting functionality to prevent API abuse
and ensure compliance with Atlassian API rate limits.
"""

import asyncio
import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from functools import wraps
from typing import Any, Callable, Optional

logger = logging.getLogger("mcp-atlassian.rate_limit")


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting."""
    
    # Maximum requests per time window
    max_requests: int = 60
    # Time window in seconds
    time_window: int = 60
    # Whether to apply exponential backoff on rate limit errors
    enable_backoff: bool = True
    # Initial backoff delay in seconds
    initial_backoff: float = 1.0
    # Maximum backoff delay in seconds
    max_backoff: float = 60.0
    # Backoff multiplier
    backoff_multiplier: float = 2.0


class RateLimiter:
    """Token bucket rate limiter implementation."""
    
    def __init__(self, config: Optional[RateLimitConfig] = None):
        """Initialize the rate limiter.
        
        Args:
            config: Rate limit configuration (uses defaults if not provided)
        """
        self.config = config or RateLimitConfig()
        # Track request timestamps per endpoint
        self.request_history: dict[str, deque] = defaultdict(deque)
        # Track backoff delays per endpoint
        self.backoff_delays: dict[str, float] = {}
        # Lock for thread safety
        self._lock = asyncio.Lock() if asyncio.get_event_loop().is_running() else None
        
    def _clean_old_requests(self, endpoint: str, current_time: float) -> None:
        """Remove requests older than the time window.
        
        Args:
            endpoint: The API endpoint
            current_time: Current timestamp
        """
        history = self.request_history[endpoint]
        cutoff_time = current_time - self.config.time_window
        
        # Remove old timestamps
        while history and history[0] < cutoff_time:
            history.popleft()
    
    def is_allowed(self, endpoint: str = "default") -> tuple[bool, float]:
        """Check if a request is allowed under rate limits.
        
        Args:
            endpoint: The API endpoint (for per-endpoint limiting)
            
        Returns:
            Tuple of (is_allowed, wait_time_if_not_allowed)
        """
        current_time = time.time()
        
        # Clean old requests
        self._clean_old_requests(endpoint, current_time)
        
        # Check backoff delay
        if endpoint in self.backoff_delays:
            backoff_until = self.backoff_delays[endpoint]
            if current_time < backoff_until:
                wait_time = backoff_until - current_time
                logger.debug(f"Rate limit backoff for {endpoint}: {wait_time:.2f}s remaining")
                return False, wait_time
            else:
                # Backoff period expired
                del self.backoff_delays[endpoint]
        
        # Check rate limit
        history = self.request_history[endpoint]
        if len(history) >= self.config.max_requests:
            # Calculate wait time until oldest request expires
            oldest_request = history[0]
            wait_time = (oldest_request + self.config.time_window) - current_time
            logger.warning(
                f"Rate limit reached for {endpoint}: {len(history)}/{self.config.max_requests} "
                f"requests in {self.config.time_window}s window. Wait {wait_time:.2f}s"
            )
            return False, max(0, wait_time)
        
        return True, 0
    
    def record_request(self, endpoint: str = "default") -> None:
        """Record a request for rate limiting.
        
        Args:
            endpoint: The API endpoint
        """
        current_time = time.time()
        self.request_history[endpoint].append(current_time)
        logger.debug(
            f"Recorded request for {endpoint}. "
            f"Total in window: {len(self.request_history[endpoint])}/{self.config.max_requests}"
        )
    
    def record_rate_limit_error(self, endpoint: str = "default", retry_after: Optional[float] = None) -> None:
        """Record a rate limit error and apply backoff.
        
        Args:
            endpoint: The API endpoint
            retry_after: Server-provided retry-after value in seconds
        """
        if not self.config.enable_backoff:
            return
        
        current_time = time.time()
        
        if retry_after:
            # Use server-provided retry-after value
            backoff_delay = retry_after
        else:
            # Calculate exponential backoff
            current_backoff = self.backoff_delays.get(endpoint, 0)
            if current_backoff == 0:
                backoff_delay = self.config.initial_backoff
            else:
                backoff_delay = min(
                    current_backoff * self.config.backoff_multiplier,
                    self.config.max_backoff
                )
        
        self.backoff_delays[endpoint] = current_time + backoff_delay
        logger.warning(
            f"Rate limit error for {endpoint}. Applying backoff of {backoff_delay:.2f}s"
        )
    
    async def wait_if_needed(self, endpoint: str = "default") -> None:
        """Wait if rate limit is exceeded (async version).
        
        Args:
            endpoint: The API endpoint
        """
        while True:
            is_allowed, wait_time = self.is_allowed(endpoint)
            if is_allowed:
                break
            
            logger.info(f"Rate limit wait for {endpoint}: {wait_time:.2f}s")
            await asyncio.sleep(wait_time)
    
    def wait_if_needed_sync(self, endpoint: str = "default") -> None:
        """Wait if rate limit is exceeded (synchronous version).
        
        Args:
            endpoint: The API endpoint
        """
        while True:
            is_allowed, wait_time = self.is_allowed(endpoint)
            if is_allowed:
                break
            
            logger.info(f"Rate limit wait for {endpoint}: {wait_time:.2f}s")
            time.sleep(wait_time)


# Global rate limiter instance
_global_rate_limiter: Optional[RateLimiter] = None


def get_rate_limiter() -> RateLimiter:
    """Get the global rate limiter instance.
    
    Returns:
        The global RateLimiter instance
    """
    global _global_rate_limiter
    if _global_rate_limiter is None:
        # Load config from environment if available
        import os
        config = RateLimitConfig()
        
        if os.getenv("RATE_LIMIT_MAX_REQUESTS"):
            config.max_requests = int(os.getenv("RATE_LIMIT_MAX_REQUESTS", "60"))
        if os.getenv("RATE_LIMIT_TIME_WINDOW"):
            config.time_window = int(os.getenv("RATE_LIMIT_TIME_WINDOW", "60"))
        if os.getenv("RATE_LIMIT_ENABLE_BACKOFF"):
            config.enable_backoff = os.getenv("RATE_LIMIT_ENABLE_BACKOFF", "true").lower() == "true"
        
        _global_rate_limiter = RateLimiter(config)
        logger.info(
            f"Rate limiter initialized: {config.max_requests} requests per {config.time_window}s"
        )
    
    return _global_rate_limiter


def rate_limit(endpoint: Optional[str] = None):
    """Decorator to apply rate limiting to a function.
    
    Args:
        endpoint: Optional endpoint name (uses function name if not provided)
        
    Returns:
        Decorated function with rate limiting
    """
    def decorator(func: Callable) -> Callable:
        endpoint_name = endpoint or func.__name__
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs) -> Any:
            limiter = get_rate_limiter()
            
            # Wait if rate limited
            limiter.wait_if_needed_sync(endpoint_name)
            
            # Record the request
            limiter.record_request(endpoint_name)
            
            try:
                # Execute the function
                result = func(*args, **kwargs)
                return result
            except Exception as e:
                # Check if it's a rate limit error (429 status code)
                if hasattr(e, 'response') and hasattr(e.response, 'status_code'):
                    if e.response.status_code == 429:
                        # Extract retry-after header if available
                        retry_after = None
                        if hasattr(e.response, 'headers'):
                            retry_after_header = e.response.headers.get('Retry-After')
                            if retry_after_header:
                                try:
                                    retry_after = float(retry_after_header)
                                except ValueError:
                                    pass
                        
                        limiter.record_rate_limit_error(endpoint_name, retry_after)
                        
                        # Log the rate limit error with security context
                        logger.error(
                            f"Rate limit exceeded for {endpoint_name}. "
                            f"Consider reducing request frequency."
                        )
                
                # Re-raise the exception
                raise
        
        @wraps(func)
        async def async_wrapper(*args, **kwargs) -> Any:
            limiter = get_rate_limiter()
            
            # Wait if rate limited
            await limiter.wait_if_needed(endpoint_name)
            
            # Record the request
            limiter.record_request(endpoint_name)
            
            try:
                # Execute the function
                result = await func(*args, **kwargs)
                return result
            except Exception as e:
                # Check if it's a rate limit error (429 status code)
                if hasattr(e, 'response') and hasattr(e.response, 'status_code'):
                    if e.response.status_code == 429:
                        # Extract retry-after header if available
                        retry_after = None
                        if hasattr(e.response, 'headers'):
                            retry_after_header = e.response.headers.get('Retry-After')
                            if retry_after_header:
                                try:
                                    retry_after = float(retry_after_header)
                                except ValueError:
                                    pass
                        
                        limiter.record_rate_limit_error(endpoint_name, retry_after)
                        
                        # Log the rate limit error with security context
                        logger.error(
                            f"Rate limit exceeded for {endpoint_name}. "
                            f"Consider reducing request frequency."
                        )
                
                # Re-raise the exception
                raise
        
        # Return appropriate wrapper based on function type
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


def reset_rate_limiter() -> None:
    """Reset the global rate limiter (useful for testing)."""
    global _global_rate_limiter
    _global_rate_limiter = None
    logger.debug("Rate limiter reset")