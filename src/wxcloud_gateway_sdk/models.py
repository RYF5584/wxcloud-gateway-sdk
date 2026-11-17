# -*- coding: utf-8 -*-
"""
Data models: GatewayConfig, GatewayRequestParams, RawHttpResponse, GatewayResponse.

Author: RYF5584
    WeChat: RSComapnyCEO
    QQ: 1043695584
    Telegram: ryf5584
    GitHub: https://github.com/RYF5584
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from urllib.parse import urlencode

from .codec import GATEWAY_PATH, V3_CONTENT_TYPE, V3_VERSION_HEADER, encode_request


@dataclass
class GatewayConfig:
    """Gateway configuration.

    Users usually only need to pass key/domain/token/rid at init time;
    the remaining gateway routing parameters have defaults and can be
    reassigned directly when needed.
    """

    key: str
    """AES key (base64 string)."""

    domain: str
    """Gateway domain."""

    token: str = ""
    """Access token."""

    rid: str = ""
    """Request ID (issued by the server)."""

    # --- Gateway routing parameters below have defaults; users rarely change them ---

    referer: str = ""
    """HTTP Referer header for the outer /call request to the gateway.

    Only affects the outer gateway HTTP request, not the encrypted inner
    business headers. When unset, it is looked up from the send_request
    headers (case-insensitive).
    """

    user_agent: str = ""
    """HTTP User-Agent header for the outer /call request to the gateway.

    Only affects the outer gateway HTTP request, not the encrypted inner
    business headers. When unset, it is looked up from the send_request
    headers (case-insensitive).
    """

    wx_target_service: str = "HTTP"
    """x-wx-target-service header."""

    wx_http_mode: str = "REROUTE"
    """x-wx-http-mode header."""

    wx_conf_version: str = "1765020855"
    """x-wx-conf-version header (gateway config version, default 1765020855)."""

    origin_base_url: str = ""
    """Base URL of the business server (e.g. https://example.com).

    When the url passed to send_request is a relative path, it is joined
    with this base automatically. Trailing/leading slashes are handled.
    """

    def __post_init__(self):
        if not self.wx_conf_version:
            self.wx_conf_version = "1765020855"

    def build_gateway_headers(self, url: str = "") -> Dict[str, str]:
        """Build HTTP headers for the outer /call request to the gateway.

        Args:
            url: Business request path (e.g. /api/v1/data).

        Returns:
            Gateway-layer HTTP headers dict.
        """
        headers: Dict[str, str] = {
            "X-WX-EV": V3_VERSION_HEADER,
            "Content-Type": V3_CONTENT_TYPE,
            "charset": "utf-8",
        }
        if self.rid:
            headers["X-WX-RID"] = self.rid
        if self.user_agent:
            headers["User-Agent"] = self.user_agent
        if self.referer:
            headers["Referer"] = self.referer
        return headers

    def build_inner_headers(self, url: str = "") -> Dict[str, str]:
        """Build inner business HTTP headers (encrypted into the body).

        Note: referer and user-agent are never taken from this config;
        inside the encrypted headers they only come from the user's
        send_request headers.

        Args:
            url: Business request path (e.g. /api/v1/data or a full URL).

        Returns:
            Gateway inner HTTP headers dict.
        """
        headers: Dict[str, str] = {
            "x-wx-target-service": self.wx_target_service,
            "x-wx-http-mode": self.wx_http_mode,
        }
        if self.wx_conf_version:
            headers["x-wx-conf-version"] = self.wx_conf_version

        if self.domain:
            headers["x-wx-http-host"] = self.domain

        # x-wx-http-path: built from url automatically, slashes handled
        final_url = self._resolve_full_url(url)
        if final_url:
            headers["x-wx-http-path"] = final_url

        return headers

    def _resolve_full_url(self, url: str) -> str:
        """Resolve url to a full URL, handling origin_base_url joining and slashes.

        - A full URL (http/https prefix) is returned as-is
        - A relative path is joined with origin_base_url when set
        - Trailing/leading slashes are handled automatically
        """
        if not url:
            return ""
        if url.startswith("http://") or url.startswith("https://"):
            return url
        if not self.origin_base_url:
            return url
        # Join, handling slashes automatically
        base = self.origin_base_url.rstrip("/")
        path = url if url.startswith("/") else "/" + url
        return base + path


@dataclass
class GatewayRequestParams:
    """Gateway request parameters before encryption.

    Call :meth:`encrypt` to produce the actual HTTP request parameters.
    """

    config: GatewayConfig
    """Gateway configuration."""

    method: str
    """HTTP method (GET/POST etc.)."""

    url: str
    """Actual request path (e.g. /api/v1/data)."""

    headers: Dict[str, str] = field(default_factory=dict)
    """Business request headers (user-defined, e.g. authorization, content-type)."""

    body: bytes = b""
    """Request body (raw binary)."""

    query: Dict[str, Any] = field(default_factory=dict)
    """URL query parameters."""

    def encrypt(self) -> Dict[str, Any]:
        """Encrypt and produce the actual HTTP request parameters.

        Merges user business headers with auto-generated gateway routing
        headers; user headers win. Dedup is case-insensitive: user-supplied
        headers override auto-generated ones with the same name.

        Returns:
            A dict with method, url, body, headers.
        """
        body_str = self.body.decode("utf-8", errors="replace") if self.body else None

        # Auto-generated inner gateway headers
        auto_headers = self.config.build_inner_headers(self.url)

        # Case-insensitive dedup: user headers have the highest priority,
        # e.g. a user-provided "Referer" removes the auto "referer"
        user_keys_lower = {k.lower() for k in self.headers.keys()}
        auto_headers = {
            k: v for k, v in auto_headers.items()
            if k.lower() not in user_keys_lower
        }

        # Merge: user business headers win
        inner_headers = {**auto_headers, **self.headers}

        packet = encode_request(
            self.config.key,
            method=self.method,
            headers=inner_headers,
            body=body_str,
        )

        gateway_url = "https://{}{}".format(self.config.domain, GATEWAY_PATH)
        gateway_query: Dict[str, Any] = dict(self.query)
        if self.config.token:
            gateway_query.setdefault("token", self.config.token)

        # Gateway routing headers (outer /call request)
        gateway_headers = self.config.build_gateway_headers(self.url)

        # When config has no UA/Referer, look them up from user headers
        # (case-insensitive)
        if not self.config.user_agent:
            for k, v in self.headers.items():
                if k.lower() == "user-agent":
                    gateway_headers["User-Agent"] = v
                    break
        if not self.config.referer:
            for k, v in self.headers.items():
                if k.lower() == "referer":
                    gateway_headers["Referer"] = v
                    break

        if gateway_query:
            gateway_url = "{}?{}".format(gateway_url, urlencode(gateway_query))

        return {
            "method": "POST",
            "url": gateway_url,
            "body": packet,
            "headers": gateway_headers,
        }


@dataclass
class RawHttpResponse:
    """Raw gateway HTTP response (debug only).

    Users normally do not need this when decryption succeeds;
    on decryption failure or gateway issues it is available via
    ``GatewayResponse.raw_http``.
    """

    status_code: int
    """Gateway-layer HTTP status code."""

    headers: Dict[str, str]
    """Gateway-layer response headers."""

    body: bytes
    """Gateway-layer encrypted body."""

    def body_base64(self) -> str:
        """Base64 encoding of the body."""
        return base64.b64encode(self.body).decode("ascii")


@dataclass
class GatewayResponse:
    """Gateway response.

    Three layers:
    - Gateway layer: ``gateway_success`` / ``gateway_body`` / ``raw_http``
    - Business layer: ``status_code`` / ``headers`` / ``body``
      (valid only when ``gateway_success=True``)
    - Debug layer: ``request_params`` / ``request_raw``

    When ``gateway_success=True``, ``status_code``/``headers``/``body`` hold the
    values returned by the business server. When ``gateway_success=False``,
    business fields are empty/zero and ``gateway_body`` / ``raw_http`` should
    be inspected instead.
    """

    # --- Gateway layer ---

    gateway_success: bool
    """Whether the gateway call succeeded (the business response was decrypted).
    Does not reflect business-level success."""

    gateway_body: Dict[str, Any]
    """Full decrypted gateway response structure (statusCode, header, body).

    - On gateway success: contains the full business server response.
    - On gateway error (e.g. -601001): contains the gateway error plaintext.
    - On decryption failure: contains the raw encrypted bytes.
    """

    raw_http: RawHttpResponse = field(default=None)  # type: ignore[assignment]
    """Raw gateway HTTP response (debug only)."""

    # --- Business layer (valid only when gateway_success=True) ---

    status_code: int = 0
    """HTTP status code returned by the business server. 0 on gateway failure."""

    headers: Dict[str, str] = field(default_factory=dict)
    """Response headers returned by the business server. Empty on gateway failure."""

    body: bytes = b""
    """Response body returned by the business server. Empty on gateway failure."""

    # --- Debug layer ---

    request_params: Optional[GatewayRequestParams] = field(default=None)
    """Request parameters before encryption (optional, for debugging)."""

    request_raw: Optional[Dict[str, Any]] = field(default=None)
    """Encrypted HTTP request parameters (optional, for debugging)."""

    def json(self) -> Any:
        """Deserialize the business body into a JSON object.

        Returns the business server's JSON response when ``gateway_success=True``;
        returns ``None`` when ``gateway_success=False`` (no business data).

        Returns:
            The deserialized JSON object, or None.
        """
        if not self.gateway_success:
            return None
        if isinstance(self.body, (bytes, bytearray)):
            return json.loads(self.body)
        return json.loads(str(self.body))

    def __repr__(self) -> str:
        if self.gateway_success:
            return (
                "GatewayResponse(gateway_success=True, "
                "status_code={}, headers={}, body={!r})".format(
                    self.status_code, self.headers, self.body[:200]
                )
            )
        else:
            return (
                "GatewayResponse(gateway_success=False, "
                "gateway_body={})".format(
                    json.dumps(self.gateway_body, ensure_ascii=False, default=str)[:300]
                )
            )
