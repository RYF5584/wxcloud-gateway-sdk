# -*- coding: utf-8 -*-
"""
Cloud Run synchronous client (based on requests).

Author: RYF5584
    WeChat: RSComapnyCEO
    QQ: 1043695584
    Telegram: ryf5584
    GitHub: https://github.com/RYF5584
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple, TypedDict, Union

import requests

from .container_client_common import (
    build_plain_response,
    build_response,
    find_redirect_location,
    resolve_body_bytes,
)
from .container_models import ContainerConfig, ContainerRequestParams, ContainerResponse


class ContainerHttpOptions(TypedDict, total=False):
    """Native requests options (Cloud Run).

    Passed through to ``requests.request()``; commonly used options below.
    """

    timeout: float
    proxies: Dict[str, str]
    verify: Union[bool, str]
    cert: Union[str, Tuple[str, str]]
    auth: Tuple[str, str]
    cookies: Dict[str, str]


class ContainerSyncClient:
    """Cloud Run synchronous client (based on requests).

    Pass key/url/timestamp at init time (obtainable via traffic capture),
    then call send_request (or the get/post convenience methods) like a
    plain HTTP client; Cloud Run V1 protocol encryption, decryption and
    routing headers are handled automatically.

    The same endpoint (url) can route to different environments and services:
    the ``env``/``service`` set at init time are defaults, and each request
    may override them via the ``env``/``service`` parameters.
    """

    def __init__(
        self,
        key: str,
        url: str,
        *,
        timestamp: str = "",
        env: str = "",
        service: str = "",
        resource_appid: str = "",
        user_timeout: Optional[int] = None,
        referer: str = "",
        user_agent: str = "",
        content_encoding: str = "PB",
        follow_redirects: bool = True,
        max_redirects: int = 6,
    ):
        """Initialize the client.

        Args:
            key: AES key (base64 string, 16 bytes when decoded).
            url: Full Cloud Run endpoint URL including the token query, e.g.
                ``https://xxxservicewechat.com/wxa-qbase/container_service?token=xxx``.
            timestamp: Value of the ``X-WX-ENCRYPTION-TIMESTAMP`` header
                (obtainable via traffic capture).
            env: Default cloud environment id (overridable per request).
            service: Default target Cloud Run service name (overridable per request).
            resource_appid: Resource-party appid (resource-party instances).
            user_timeout: User timeout in seconds.
            referer: Outer HTTP Referer header.
            user_agent: Outer HTTP User-Agent header.
            content_encoding: Request payload encoding (``"PB"`` or ``"JSON"``).
            follow_redirects: Whether to follow business 3xx redirects (default True).
            max_redirects: Maximum number of redirects (default 6, matching WACloud).
        """
        self.config = ContainerConfig(
            key=key,
            url=url,
            timestamp=timestamp,
            env=env,
            service=service,
            resource_appid=resource_appid,
            user_timeout=user_timeout,
            referer=referer,
            user_agent=user_agent,
            content_encoding=content_encoding,
        )
        self.follow_redirects = follow_redirects
        """Whether to follow business 3xx redirects automatically."""

        self.max_redirects = max_redirects
        """Maximum number of redirects."""

    # ------------------------------------------------------------------
    # Generic request entry point
    # ------------------------------------------------------------------

    def send_request(
        self,
        method: str = "GET",
        path: str = "/",
        *,
        headers: Optional[Dict[str, Any]] = None,
        query: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,  # noqa: A002
        body: Optional[Union[str, bytes]] = None,
        env: Optional[str] = None,
        service: Optional[str] = None,
        user_timeout: Optional[int] = None,
        **http_options: Any,
    ) -> ContainerResponse:
        """Send an encrypted request and return the decrypted response.

        Pass method, path and business headers like a plain HTTP client;
        Cloud Run encryption and routing parameters are injected automatically.

        Args:
            method: HTTP method (GET/POST etc.).
            path: Business request path (e.g. ``/api/v1/data``).
            headers: Business request headers (e.g. authorization, content-type).
            query: URL query parameters (appended to path).
            data: Form data (mutually exclusive with json/body).
            json: JSON request body (mutually exclusive with data/body).
            body: Raw request body (mutually exclusive with data/json).
            env: Cloud environment id (overrides config.env per request).
            service: Target service name (overrides config.service per request).
            user_timeout: User timeout in seconds (overrides config.user_timeout).
            **http_options: Native requests options (see :class:`ContainerHttpOptions`).

        Returns:
            The decrypted :class:`ContainerResponse`; ``status_code``/``headers``/
            ``body`` hold the container service's values.
        """
        body_bytes = resolve_body_bytes(data, json, body)

        request_params = ContainerRequestParams(
            config=self.config,
            method=method,
            path=path,
            headers=headers or {},
            query=query or {},
            body=body_bytes,
            env=env or "",
            service=service or "",
            user_timeout=user_timeout,
        )

        return self._send_encrypted(request_params, **http_options)

    # ------------------------------------------------------------------
    # Convenience methods by request type
    # ------------------------------------------------------------------

    def get(
        self,
        path: str = "/",
        *,
        headers: Optional[Dict[str, Any]] = None,
        query: Optional[Dict[str, Any]] = None,
        env: Optional[str] = None,
        service: Optional[str] = None,
        user_timeout: Optional[int] = None,
        **http_options: Any,
    ) -> ContainerResponse:
        """Send a GET request.

        Args:
            path: Business request path.
            headers: Business request headers.
            query: URL query parameters (appended to path).
            env: Cloud environment id (overrides config.env per request).
            service: Target service name (overrides config.service per request).
            user_timeout: User timeout in seconds.
            **http_options: Native requests options.

        Returns:
            The decrypted :class:`ContainerResponse`.
        """
        return self.send_request(
            "GET", path, headers=headers, query=query, env=env,
            service=service, user_timeout=user_timeout, **http_options,
        )

    def post(
        self,
        path: str = "/",
        *,
        headers: Optional[Dict[str, Any]] = None,
        query: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,  # noqa: A002
        body: Optional[Union[str, bytes]] = None,
        env: Optional[str] = None,
        service: Optional[str] = None,
        user_timeout: Optional[int] = None,
        **http_options: Any,
    ) -> ContainerResponse:
        """Send a POST request.

        Args:
            path: Business request path.
            headers: Business request headers.
            query: URL query parameters (appended to path).
            data: Form data (mutually exclusive with json/body).
            json: JSON request body (mutually exclusive with data/body).
            body: Raw request body (mutually exclusive with data/json).
            env: Cloud environment id (overrides config.env per request).
            service: Target service name (overrides config.service per request).
            user_timeout: User timeout in seconds.
            **http_options: Native requests options.

        Returns:
            The decrypted :class:`ContainerResponse`.
        """
        return self.send_request(
            "POST", path, headers=headers, query=query, data=data, json=json,
            body=body, env=env, service=service, user_timeout=user_timeout,
            **http_options,
        )

    def put(
        self,
        path: str = "/",
        *,
        headers: Optional[Dict[str, Any]] = None,
        query: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,  # noqa: A002
        body: Optional[Union[str, bytes]] = None,
        env: Optional[str] = None,
        service: Optional[str] = None,
        user_timeout: Optional[int] = None,
        **http_options: Any,
    ) -> ContainerResponse:
        """Send a PUT request. Same parameters as :meth:`post`."""
        return self.send_request(
            "PUT", path, headers=headers, query=query, data=data, json=json,
            body=body, env=env, service=service, user_timeout=user_timeout,
            **http_options,
        )

    def patch(
        self,
        path: str = "/",
        *,
        headers: Optional[Dict[str, Any]] = None,
        query: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,  # noqa: A002
        body: Optional[Union[str, bytes]] = None,
        env: Optional[str] = None,
        service: Optional[str] = None,
        user_timeout: Optional[int] = None,
        **http_options: Any,
    ) -> ContainerResponse:
        """Send a PATCH request. Same parameters as :meth:`post`."""
        return self.send_request(
            "PATCH", path, headers=headers, query=query, data=data, json=json,
            body=body, env=env, service=service, user_timeout=user_timeout,
            **http_options,
        )

    def delete(
        self,
        path: str = "/",
        *,
        headers: Optional[Dict[str, Any]] = None,
        query: Optional[Dict[str, Any]] = None,
        env: Optional[str] = None,
        service: Optional[str] = None,
        user_timeout: Optional[int] = None,
        **http_options: Any,
    ) -> ContainerResponse:
        """Send a DELETE request.

        Args:
            path: Business request path.
            headers: Business request headers.
            query: URL query parameters (appended to path).
            env: Cloud environment id (overrides config.env per request).
            service: Target service name (overrides config.service per request).
            user_timeout: User timeout in seconds.
            **http_options: Native requests options.

        Returns:
            The decrypted :class:`ContainerResponse`.
        """
        return self.send_request(
            "DELETE", path, headers=headers, query=query, env=env,
            service=service, user_timeout=user_timeout, **http_options,
        )

    # ------------------------------------------------------------------
    # Internal implementation
    # ------------------------------------------------------------------

    def _send_encrypted(
        self, params: ContainerRequestParams, **http_options: Any
    ) -> ContainerResponse:
        """Send the encrypted request and handle business 3xx redirects.

        - Relative-path Location: re-encrypt and resend to the same endpoint
          (up to max_redirects times);
        - Absolute-URL Location: forward the original request over plaintext
          HTTP per WACloud behavior, without decrypting.
        """
        current = params
        redirects = 0

        while True:
            request_raw = current.encrypt()

            # Empty UA/Referer when unset, preventing requests from injecting its own
            final_headers = dict(request_raw["headers"])
            if "User-Agent" not in final_headers:
                final_headers["User-Agent"] = ""
            if "Referer" not in final_headers:
                final_headers["Referer"] = ""

            send_options = dict(http_options)
            send_options.setdefault("allow_redirects", False)

            response = requests.request(
                method=request_raw["method"],
                url=request_raw["url"],
                data=request_raw["body"],
                headers=final_headers,
                **send_options,
            )

            container_response = build_response(
                self.config.key,
                http_status=response.status_code,
                http_headers=dict(response.headers),
                http_body=response.content,
                request_params=current,
                request_raw=request_raw,
            )

            if not self.follow_redirects:
                return container_response

            location = find_redirect_location(container_response)
            if not location or redirects >= self.max_redirects:
                return container_response
            redirects += 1

            if location.startswith("http://") or location.startswith("https://"):
                # Absolute URL: plaintext forward (WACloud behavior), no re-encryption
                return self._send_plain_redirect(
                    current, location, request_raw, **http_options
                )

            # Relative path: re-encrypt and resend to the same endpoint;
            # the call_id stays unchanged
            current = ContainerRequestParams(
                config=self.config,
                method=current.method,
                path=location,
                headers=current.headers,
                query={},
                body=current.body,
                env=current.env,
                service=current.service,
                user_timeout=current.user_timeout,
                call_id=current.call_id,
            )

    def _send_plain_redirect(
        self,
        params: ContainerRequestParams,
        location: str,
        request_raw: Dict[str, Any],
        **http_options: Any,
    ) -> ContainerResponse:
        """Forward in plaintext to the absolute-URL redirect address
        (WACloud behavior)."""
        send_options = dict(http_options)
        send_options.setdefault("allow_redirects", False)

        response = requests.request(
            method=params.method,
            url=location,
            data=params.body,
            headers=params.build_merged_inner_headers(),
            **send_options,
        )
        return build_plain_response(
            http_status=response.status_code,
            http_headers=dict(response.headers),
            http_body=response.content,
            request_params=params,
            request_raw={**request_raw, "url": location, "encrypted": False},
        )
