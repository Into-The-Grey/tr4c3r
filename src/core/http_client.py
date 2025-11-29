"""Asynchronous HTTP client helper.

This module provides a wrapper around the `httpx` asynchronous client used by
TR4C3R modules.  It centralises settings such as timeouts, headers and retry
behaviour, and exposes methods for making GET/POST requests.  Having a single
client instance allows for connection pooling and reduces overhead.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, Optional, Set

import httpx


# HTTP status codes that should not trigger retries
NON_RETRYABLE_STATUS_CODES: Set[int] = {
    400,  # Bad Request
    401,  # Unauthorized
    403,  # Forbidden
    404,  # Not Found
    405,  # Method Not Allowed
    410,  # Gone
    422,  # Unprocessable Entity
}


class AsyncHTTPClient:
    """A simple async HTTP client with basic retry logic and improved error handling."""

    DEFAULT_USER_AGENT = "TR4C3R/1.0 (+https://github.com/tr4c3r)"

    def __init__(
        self,
        timeout: float = 10.0,
        max_retries: int = 3,
        retry_on_status: Optional[Set[int]] = None,
    ) -> None:
        """Initialize the HTTP client.

        Parameters
        ----------
        timeout : float
            Request timeout in seconds.
        max_retries : int
            Maximum number of retry attempts.
        retry_on_status : set, optional
            HTTP status codes that should trigger retries.
            Defaults to 429, 500, 502, 503, 504.
        """
        self._timeout = timeout
        self._max_retries = max_retries
        self._retry_on_status = retry_on_status or {429, 500, 502, 503, 504}
        self._client: Optional[httpx.AsyncClient] = None
        self.logger = logging.getLogger(self.__class__.__name__)
        self._request_count = 0
        self._total_request_time = 0.0

    async def __aenter__(self) -> "AsyncHTTPClient":
        self._client = httpx.AsyncClient(
            timeout=self._timeout,
            headers={"User-Agent": self.DEFAULT_USER_AGENT},
            follow_redirects=True,
        )
        self.logger.debug(
            "HTTP client initialized (timeout=%.1fs, max_retries=%d)",
            self._timeout,
            self._max_retries,
        )
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._client is not None:
            await self._client.aclose()
            if self._request_count > 0:
                avg_time = self._total_request_time / self._request_count
                self.logger.debug(
                    "HTTP client closed (requests=%d, avg_time=%.2fms)",
                    self._request_count,
                    avg_time * 1000,
                )

    def _should_retry(self, status_code: int) -> bool:
        """Determine if a request should be retried based on status code."""
        if status_code in NON_RETRYABLE_STATUS_CODES:
            return False
        return status_code in self._retry_on_status

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Any] = None,
        data: Optional[Any] = None,
        raise_for_status: bool = True,
    ) -> httpx.Response:
        """Make an HTTP request with smart retry/backoff.

        Parameters
        ----------
        method : str
            HTTP method (GET, POST, etc.).
        url : str
            The URL to request.
        headers : dict, optional
            HTTP headers.
        params : dict, optional
            Query parameters.
        json : Any, optional
            JSON body for POST/PUT requests.
        data : Any, optional
            Form data for POST/PUT requests.
        raise_for_status : bool
            Whether to raise exception for 4xx/5xx status codes.

        Returns
        -------
        httpx.Response
            The HTTP response.

        Raises
        ------
        RuntimeError
            If the client is not used as a context manager.
        httpx.HTTPStatusError
            If raise_for_status is True and the response has an error status.
        """
        if self._client is None:
            raise RuntimeError("AsyncHTTPClient must be used as an async context manager")

        start_time = time.time()
        attempt = 0
        last_exc: Optional[Exception] = None

        while attempt < self._max_retries:
            try:
                self.logger.debug(
                    "%s %s (attempt %d/%d)",
                    method,
                    url[:100],
                    attempt + 1,
                    self._max_retries,
                )
                response = await self._client.request(
                    method,
                    url,
                    headers=headers,
                    params=params,
                    json=json,
                    data=data,
                )

                # Track request metrics
                elapsed = time.time() - start_time
                self._request_count += 1
                self._total_request_time += elapsed

                # Log response info
                self.logger.debug(
                    "%s %s -> %d (%.2fms)",
                    method,
                    url[:100],
                    response.status_code,
                    elapsed * 1000,
                )

                # Check if we should retry based on status code
                if response.status_code >= 400:
                    if self._should_retry(response.status_code):
                        self.logger.warning(
                            "Retryable status %d for %s, retrying...",
                            response.status_code,
                            url[:100],
                        )
                        attempt += 1
                        await asyncio.sleep(2**attempt)
                        continue
                    elif raise_for_status:
                        response.raise_for_status()

                return response

            except httpx.TimeoutException as exc:
                last_exc = exc
                self.logger.warning(
                    "Timeout on %s %s (attempt %d/%d): %s",
                    method,
                    url[:100],
                    attempt + 1,
                    self._max_retries,
                    exc,
                )
                attempt += 1
                await asyncio.sleep(2**attempt)

            except httpx.RequestError as exc:
                last_exc = exc
                self.logger.warning(
                    "Request error on %s %s (attempt %d/%d): %s",
                    method,
                    url[:100],
                    attempt + 1,
                    self._max_retries,
                    exc,
                )
                attempt += 1
                await asyncio.sleep(2**attempt)

            except httpx.HTTPStatusError as exc:
                # Don't retry non-retryable status codes
                if exc.response.status_code in NON_RETRYABLE_STATUS_CODES:
                    self.logger.debug(
                        "Non-retryable status %d for %s",
                        exc.response.status_code,
                        url[:100],
                    )
                    raise
                last_exc = exc
                self.logger.warning(
                    "HTTP error %d on %s (attempt %d/%d)",
                    exc.response.status_code,
                    url[:100],
                    attempt + 1,
                    self._max_retries,
                )
                attempt += 1
                await asyncio.sleep(2**attempt)

        # All attempts failed
        self.logger.error(
            "All %d attempts failed for %s %s",
            self._max_retries,
            method,
            url[:100],
        )
        if last_exc:
            raise last_exc
        raise RuntimeError("HTTP request failed without exception")

    async def get(
        self,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        raise_for_status: bool = True,
        timeout: Optional[float] = None,
    ) -> httpx.Response:
        """Make a GET request.

        Parameters
        ----------
        url : str
            The URL to request.
        headers : dict, optional
            HTTP headers.
        params : dict, optional
            Query parameters.
        raise_for_status : bool
            Whether to raise exception for 4xx/5xx status codes.
        timeout : float, optional
            Request timeout override in seconds.

        Returns
        -------
        httpx.Response
            The HTTP response.
        """
        # Note: timeout is configured at client level, this param is for compatibility
        _ = timeout  # Ignored - use client-level timeout
        return await self.request(
            "GET",
            url,
            headers=headers,
            params=params,
            raise_for_status=raise_for_status,
        )

    async def post(
        self,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Any] = None,
        data: Optional[Any] = None,
        raise_for_status: bool = True,
    ) -> httpx.Response:
        """Make a POST request.

        Parameters
        ----------
        url : str
            The URL to request.
        headers : dict, optional
            HTTP headers.
        params : dict, optional
            Query parameters.
        json : Any, optional
            JSON body.
        data : Any, optional
            Form data.
        raise_for_status : bool
            Whether to raise exception for 4xx/5xx status codes.

        Returns
        -------
        httpx.Response
            The HTTP response.
        """
        return await self.request(
            "POST",
            url,
            headers=headers,
            params=params,
            json=json,
            data=data,
            raise_for_status=raise_for_status,
        )

    @property
    def stats(self) -> Dict[str, Any]:
        """Get request statistics.

        Returns
        -------
        dict
            Statistics including request count and average time.
        """
        return {
            "request_count": self._request_count,
            "total_time_ms": self._total_request_time * 1000,
            "avg_time_ms": (
                (self._total_request_time / self._request_count * 1000)
                if self._request_count > 0
                else 0
            ),
        }
