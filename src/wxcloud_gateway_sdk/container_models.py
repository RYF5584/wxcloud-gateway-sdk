# -*- coding: utf-8 -*-
"""
Cloud Run data models: ContainerConfig, ContainerRequestParams, ContainerResponse.

Author: RYF5584
    WeChat: RSComapnyCEO
    QQ: 1043695584
    Telegram: ryf5584
    GitHub: https://github.com/RYF5584
"""

from __future__ import annotations

import json
import random
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from urllib.parse import urlencode

from .container_codec import (
    CONTAINER_ENCRYPTION_VERSION,
    CONTAINER_LIB_BUILD_TS,
    CONTAINER_SERVICE_PATH,
    CONTAINER_STREAM_PATH,
    encode_container_request,
)
from .models import RawHttpResponse

#: System error code: token expired/invalid (response header
#: ``x-wx-system-error: 85104``)
SYSTEM_ERROR_TOKEN_EXPIRED = 85104

#: System error code: server-side rate limiting (response header
#: ``x-wx-system-error: 102003``)
SYSTEM_ERROR_RATE_LIMIT = 102003


@dataclass
class ContainerConfig:
    """Cloud Run configuration.

    key/url/timestamp can all be obtained via traffic capture
    (see the README) or constructed from the ``tcbapi_get_service_info``
    response.
    """

    key: str
    """AES key (base64 string, 16 bytes when decoded)."""

    url: str
    """Full Cloud Run endpoint URL including the token query, e.g.
    ``https://xxxservicewechat.com/wxa-qbase/container_service?token=xxx``."""

    timestamp: str = ""
    """Value of the ``X-WX-ENCRYPTION-TIMESTAMP`` header (the timestamp field
    of the get_service_info response)."""

    env: str = ""
    """Cloud environment id (``x-wx-env`` business header)."""

    service: str = ""
    """Default target Cloud Run service name (``x-wx-service`` business header).

    Each send_request call may override it with the ``service`` parameter.
    """

    resource_appid: str = ""
    """Resource-party appid (``x-wx-resource-appid`` business header of
    resource-party instances)."""

    user_timeout: Optional[int] = None
    """User timeout in seconds; injected into both the outer
    ``X-WX-USER-TIMEOUT`` and the inner ``x-wx-user-timeout`` headers.

    Distinct from the HTTP-layer timeout, which is passed via the client's
    ``**http_options``.
    """

    # --- Protocol parameters below have defaults; users rarely change them ---

    referer: str = ""
    """Referer header of the outer HTTP request. When unset, looked up from
    the send_request headers."""

    user_agent: str = ""
    """User-Agent header of the outer HTTP request. When unset, looked up from
    the send_request headers."""

    content_encoding: str = "PB"
    """Request payload encoding (``X-WX-REQUEST-CONTENT-ENCODING``),
    ``"PB"`` or ``"JSON"``."""

    request_compression: str = "snappy"
    """Request compression (``X-WX-COMPRESSION``); currently fixed to
    ``"snappy"``."""

    lib_build_ts: int = CONTAINER_LIB_BUILD_TS
    """Value of the ``X-WX-LIB-BUILD-TS`` header (SDK build timestamp,
    matching WACloud.js)."""

    def build_encryption_headers(self) -> Dict[str, str]:
        """Build HTTP headers sent to Cloud Run (outer encryption protocol headers).

        Returns:
            Outer HTTP headers dict.
        """
        headers: Dict[str, str] = {
            "X-WX-ENCRYPTION-VERSION": CONTAINER_ENCRYPTION_VERSION,
            "X-WX-ENCRYPTION-TIMESTAMP": self.timestamp,
            "X-WX-COMPRESSION": self.request_compression,
            "X-WX-LIB-BUILD-TS": str(self.lib_build_ts),
            "X-WX-RESPONSE-CONTENT-ACCEPT-ENCODING": "PB, JSON",
            "Content-Type": "application/octet-stream",
            "X-WX-REQUEST-CONTENT-ENCODING": self.content_encoding,
        }
        if self.user_timeout is not None:
            headers["X-WX-USER-TIMEOUT"] = str(self.user_timeout)
        if self.user_agent:
            headers["User-Agent"] = self.user_agent
        if self.referer:
            headers["Referer"] = self.referer
        return headers

    def build_inner_headers(
        self,
        path: str,
        call_id: str,
        env: str = "",
        service: str = "",
        user_timeout: Optional[int] = None,
    ) -> Dict[str, str]:
        """Build inner Cloud Run business HTTP headers (encrypted into the body).

        Args:
            path: Business request path (e.g. ``/api/v1/data``, may include query).
            call_id: Call id of this invocation.
            env: Cloud environment id, overriding the config default.
            service: Target service name, overriding the config default.
            user_timeout: User timeout in seconds, overriding the config default.

        Returns:
            Inner business headers dict.
        """
        headers: Dict[str, str] = {
            "x-wx-call-id": call_id,
            "x-wx-container-path": path if path.startswith("/") else "/" + path,
        }

        resolved_env = env or self.env
        if resolved_env:
            headers["x-wx-env"] = resolved_env

        resolved_service = service or self.service
        if resolved_service:
            headers["x-wx-service"] = resolved_service

        if self.resource_appid:
            headers["x-wx-resource-appid"] = self.resource_appid

        resolved_timeout = user_timeout if user_timeout is not None else self.user_timeout
        if resolved_timeout is not None:
            headers["x-wx-user-timeout"] = str(resolved_timeout)
        return headers

    @property
    def stream_url(self) -> str:
        """Streaming (enableChunked) endpoint URL.

        Replaces ``/wxa-qbase/container_service`` in url with
        ``/wxa-qbase-stream/container_stream``; returns url unchanged when it
        does not contain that path.
        """
        if CONTAINER_SERVICE_PATH in self.url:
            return self.url.replace(CONTAINER_SERVICE_PATH, CONTAINER_STREAM_PATH)
        return self.url


@dataclass
class ContainerRequestParams:
    """Cloud Run request parameters before encryption.

    Call :meth:`encrypt` to produce the actual HTTP request parameters.
    """

    config: ContainerConfig
    """Cloud Run configuration."""

    method: str
    """HTTP method (GET/POST etc.)."""

    path: str = "/"
    """Business request path (e.g. ``/api/v1/data``); injected into the
    ``x-wx-container-path`` header."""

    headers: Dict[str, str] = field(default_factory=dict)
    """Business request headers (user-defined, e.g. authorization, content-type)."""

    query: Dict[str, Any] = field(default_factory=dict)
    """URL query parameters (appended to path before injecting
    ``x-wx-container-path``)."""

    body: bytes = b""
    """Request body (raw binary)."""

    service: str = ""
    """Target service name (overrides config.service per request)."""

    env: str = ""
    """Cloud environment id (overrides config.env per request; the same
    endpoint can route to different environments)."""

    user_timeout: Optional[int] = None
    """User timeout in seconds (overrides config.user_timeout per request)."""

    call_id: str = field(
        default_factory=lambda: "{}_{}".format(random.random(), int(time.time() * 1000))
    )
    """Call id of this invocation (auto-generated, matching WACloud format)."""

    def _resolve_path_with_query(self) -> str:
        """Append query parameters to the path."""
        path = self.path if self.path.startswith("/") else "/" + self.path
        if self.query:
            path = "{}?{}".format(path, urlencode(self.query))
        return path

    def build_merged_inner_headers(self) -> Dict[str, str]:
        """Build merged inner business headers (auto ``x-wx-*`` routing
        headers + user headers).

        User headers have the highest priority with case-insensitive dedup:
        user-supplied headers override auto-generated ones with the same name.

        Returns:
            The merged inner headers dict.
        """
        auto_headers = self.config.build_inner_headers(
            self._resolve_path_with_query(),
            self.call_id,
            env=self.env,
            service=self.service,
            user_timeout=self.user_timeout,
        )
        user_keys_lower = {k.lower() for k in self.headers.keys()}
        auto_headers = {
            k: v for k, v in auto_headers.items()
            if k.lower() not in user_keys_lower
        }
        return {**auto_headers, **self.headers}

    def encrypt(self) -> Dict[str, Any]:
        """Encrypt and produce the actual HTTP request parameters.

        Inner business headers get the auto ``x-wx-*`` routing headers injected;
        user headers win (case-insensitive dedup). Outer encryption protocol
        headers are generated from the config.

        Returns:
            A dict with method, url, body, headers, call_id.
        """
        packet = encode_container_request(
            self.config.key,
            method=self.method,
            headers=self.build_merged_inner_headers(),
            body=self.body,
            encoding=self.config.content_encoding,
            call_id=self.call_id,
        )

        # Outer encryption protocol headers
        outer_headers = self.config.build_encryption_headers()

        # When config has no UA/Referer, look them up from user headers
        # (case-insensitive)
        if not self.config.user_agent:
            for k, v in self.headers.items():
                if k.lower() == "user-agent":
                    outer_headers["User-Agent"] = v
                    break
        if not self.config.referer:
            for k, v in self.headers.items():
                if k.lower() == "referer":
                    outer_headers["Referer"] = v
                    break

        return {
            "method": "POST",
            "url": self.config.url,
            "body": packet,
            "headers": outer_headers,
            "call_id": self.call_id,
        }


@dataclass
class ContainerResponse:
    """Cloud Run response.

    Three layers:
    - Channel layer: ``container_success`` / ``container_body`` / ``raw_http`` /
      ``system_error``
    - Business layer: ``status_code`` / ``headers`` / ``body``
      (valid only when ``container_success=True``)
    - Debug layer: ``request_params`` / ``request_raw``

    When ``container_success=True``, ``status_code``/``headers``/``body`` hold
    the values returned by the container service. On token expiry (85104) or
    rate limiting (102003), ``container_success=False`` and the cause is
    available via ``token_expired``/``rate_limited``.
    """

    # --- Channel layer ---

    container_success: bool
    """Whether the Cloud Run channel succeeded (the container response was
    decrypted). Does not reflect business-level success."""

    container_body: Dict[str, Any]
    """Full decrypted Cloud Run response structure (statusCode, header, body...).

    - On channel success: contains the full container service response.
    - On system error (x-wx-system-error): contains the raw encrypted bytes.
    - On decryption failure: contains the raw encrypted bytes.
    """

    system_error: Optional[int] = None
    """Error code of the outer response header ``x-wx-system-error``
    (None when there is no system error)."""

    raw_http: RawHttpResponse = field(default=None)  # type: ignore[assignment]
    """Raw Cloud Run HTTP response (debug only)."""

    # --- Business layer (valid only when container_success=True) ---

    status_code: int = 0
    """HTTP status code returned by the container service. 0 on channel failure."""

    headers: Dict[str, str] = field(default_factory=dict)
    """Response headers returned by the container service. Empty on channel failure."""

    body: bytes = b""
    """Response body returned by the container service. Empty on channel failure."""

    # --- Debug layer ---

    request_params: Optional[ContainerRequestParams] = field(default=None)
    """Request parameters before encryption (optional, for debugging)."""

    request_raw: Optional[Dict[str, Any]] = field(default=None)
    """Encrypted HTTP request parameters (optional, for debugging)."""

    @property
    def call_id(self) -> str:
        """Call id of this invocation (from the request parameters)."""
        if self.request_params is not None:
            return self.request_params.call_id
        return ""

    @property
    def token_expired(self) -> bool:
        """Whether the token has expired/become invalid
        (``x-wx-system-error: 85104``).

        When True, re-obtain key/token and update the config.
        """
        return self.system_error == SYSTEM_ERROR_TOKEN_EXPIRED

    @property
    def rate_limited(self) -> bool:
        """Whether the request was rate-limited by the server
        (``x-wx-system-error: 102003``)."""
        return self.system_error == SYSTEM_ERROR_RATE_LIMIT

    def json(self) -> Any:
        """Deserialize the business body into a JSON object.

        Returns the container service's JSON response when
        ``container_success=True``; returns ``None`` when
        ``container_success=False`` (no business data).

        Returns:
            The deserialized JSON object, or None.
        """
        if not self.container_success:
            return None
        if isinstance(self.body, (bytes, bytearray)):
            return json.loads(self.body)
        return json.loads(str(self.body))

    def __repr__(self) -> str:
        if self.container_success:
            return (
                "ContainerResponse(container_success=True, "
                "status_code={}, headers={}, body={!r})".format(
                    self.status_code, self.headers, self.body[:200]
                )
            )
        else:
            return (
                "ContainerResponse(container_success=False, "
                "system_error={}, container_body={})".format(
                    self.system_error,
                    json.dumps(self.container_body, ensure_ascii=False, default=str)[:300],
                )
            )
