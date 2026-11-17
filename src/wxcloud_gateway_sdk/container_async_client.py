# -*- coding: utf-8 -*-
"""
Cloud Run asynchronous client (based on aiohttp), with streaming
(enableChunked) support.

Author: RYF5584
    WeChat: RSComapnyCEO
    QQ: 1043695584
    Telegram: ryf5584
    GitHub: https://github.com/RYF5584
"""

from __future__ import annotations

from typing import Any, AsyncIterator, Dict, Optional, TypedDict, Union

import aiohttp

from .container_client_common import (
    build_plain_response,
    build_response,
    find_redirect_location,
    get_header,
    parse_system_error,
    resolve_body_bytes,
)
from .container_codec import decode_container_response
from .container_models import (
    ContainerConfig,
    ContainerRequestParams,
    ContainerResponse,
)
from .models import RawHttpResponse


class ContainerAsyncHttpOptions(TypedDict, total=False):
    """Native aiohttp options (Cloud Run).

    Passed through to ``aiohttp.ClientSession.request()``; commonly used
    options below.
    """

    timeout: aiohttp.ClientTimeout
    proxy: str
    ssl: bool
    connector: aiohttp.BaseConnector
    cookies: Dict[str, str]
    auth: aiohttp.BasicAuth


class ContainerAsyncClient:
    """Cloud Run asynchronous client (based on aiohttp).

    Behaves like :class:`ContainerSyncClient` including business 3xx
    redirect following, and additionally provides the streaming interface
    :meth:`send_stream_request` (enableChunked, decrypting chunk by chunk).

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

    async def send_request(
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
        """Send an encrypted request asynchronously and return the decrypted response.

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
            **http_options: Native aiohttp options (see :class:`ContainerAsyncHttpOptions`).

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

        return await self._send_encrypted(request_params, **http_options)

    # ------------------------------------------------------------------
    # Convenience methods by request type
    # ------------------------------------------------------------------

    async def get(
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
        """Send a GET request asynchronously.
        Same parameters as :meth:`send_request` (no body parameters)."""
        return await self.send_request(
            "GET", path, headers=headers, query=query, env=env,
            service=service, user_timeout=user_timeout, **http_options,
        )

    async def post(
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
        """Send a POST request asynchronously.

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
            **http_options: Native aiohttp options.

        Returns:
            The decrypted :class:`ContainerResponse`.
        """
        return await self.send_request(
            "POST", path, headers=headers, query=query, data=data, json=json,
            body=body, env=env, service=service, user_timeout=user_timeout,
            **http_options,
        )

    async def put(
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
        """Send a PUT request asynchronously. Same parameters as :meth:`post`."""
        return await self.send_request(
            "PUT", path, headers=headers, query=query, data=data, json=json,
            body=body, env=env, service=service, user_timeout=user_timeout,
            **http_options,
        )

    async def patch(
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
        """Send a PATCH request asynchronously. Same parameters as :meth:`post`."""
        return await self.send_request(
            "PATCH", path, headers=headers, query=query, data=data, json=json,
            body=body, env=env, service=service, user_timeout=user_timeout,
            **http_options,
        )

    async def delete(
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
        """Send a DELETE request asynchronously.
        Same parameters as :meth:`send_request` (no body parameters)."""
        return await self.send_request(
            "DELETE", path, headers=headers, query=query, env=env,
            service=service, user_timeout=user_timeout, **http_options,
        )

    async def _send_encrypted(
        self, params: ContainerRequestParams, **http_options: Any
    ) -> ContainerResponse:
        """Send the encrypted request and handle business 3xx redirects
        (same logic as the sync client)."""
        current = params
        redirects = 0

        while True:
            request_raw = current.encrypt()

            # Empty UA/Referer when unset, preventing aiohttp from injecting its own
            final_headers = dict(request_raw["headers"])
            if "User-Agent" not in final_headers:
                final_headers["User-Agent"] = ""
            if "Referer" not in final_headers:
                final_headers["Referer"] = ""

            send_options = dict(http_options)
            send_options.setdefault("allow_redirects", False)

            async with aiohttp.ClientSession() as session:
                async with session.request(
                    method=request_raw["method"],
                    url=request_raw["url"],
                    data=request_raw["body"],
                    headers=final_headers,
                    **send_options,
                ) as response:
                    resp_bytes = await response.read()
                    resp_headers = {k: v for k, v in response.headers.items()}
                    resp_status = response.status

            container_response = build_response(
                self.config.key,
                http_status=resp_status,
                http_headers=resp_headers,
                http_body=resp_bytes,
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
                return await self._send_plain_redirect(
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

    async def _send_plain_redirect(
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

        async with aiohttp.ClientSession() as session:
            async with session.request(
                method=params.method,
                url=location,
                data=params.body,
                headers=params.build_merged_inner_headers(),
                **send_options,
            ) as response:
                resp_bytes = await response.read()
                resp_headers = {k: v for k, v in response.headers.items()}
                resp_status = response.status

        return build_plain_response(
            http_status=resp_status,
            http_headers=resp_headers,
            http_body=resp_bytes,
            request_params=params,
            request_raw={**request_raw, "url": location, "encrypted": False},
        )

    # ------------------------------------------------------------------
    # Streaming (enableChunked)
    # ------------------------------------------------------------------

    async def send_stream_request(
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
    ) -> AsyncIterator[ContainerResponse]:
        """Send an encrypted request in streaming mode, decrypting and
        yielding responses chunk by chunk.

        Uses the Cloud Run streaming endpoint
        (``/wxa-qbase-stream/container_stream``); at the protocol level each
        HTTP chunk is an independent V1 encrypted packet, decrypted into a
        :class:`ContainerResponse` and yielded one by one (the first chunk
        usually carries the full response headers, subsequent chunks carry
        incremental body data).

        Args:
            Same parameters as :meth:`send_request`.

        Yields:
            One :class:`ContainerResponse` per successfully decrypted chunk.
            On an outer system error (e.g. token expiry), a single failed
            response is yielded and the iteration ends.

        Note:
            Streaming responses do not follow business 3xx redirects.
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

        request_raw = request_params.encrypt()

        # Empty UA/Referer when unset, preventing aiohttp from injecting its own
        final_headers = dict(request_raw["headers"])
        if "User-Agent" not in final_headers:
            final_headers["User-Agent"] = ""
        if "Referer" not in final_headers:
            final_headers["Referer"] = ""

        send_options = dict(http_options)

        async with aiohttp.ClientSession() as session:
            async with session.request(
                method=request_raw["method"],
                url=self.config.stream_url,
                data=request_raw["body"],
                headers=final_headers,
                **send_options,
            ) as response:
                resp_headers = {k: v for k, v in response.headers.items()}

                # Outer system errors (e.g. token expiry 85104 /
                # rate limiting 102003) return immediately
                system_error = parse_system_error(resp_headers)
                if system_error is not None:
                    raw_http = RawHttpResponse(
                        status_code=response.status,
                        headers=resp_headers,
                        body=b"",
                    )
                    yield ContainerResponse(
                        container_success=False,
                        container_body={"raw": b""},
                        system_error=system_error,
                        raw_http=raw_http,
                        request_params=request_params,
                        request_raw=request_raw,
                    )
                    return

                compression = get_header(resp_headers, "x-wx-compression") or None
                content_encoding = (
                    get_header(resp_headers, "x-wx-response-content-encoding") or None
                )

                # Each HTTP chunk is one independent, complete V1 encrypted
                # packet; TCP fragmentation may split a chunk across
                # transports, so aggregate in a buffer until it decrypts
                buffer = b""
                async for chunk in response.content.iter_any():
                    buffer += chunk
                    if not buffer:
                        continue
                    container_response = self._decode_stream_packet(
                        buffer,
                        compression=compression,
                        content_encoding=content_encoding,
                        request_params=request_params,
                        request_raw=request_raw,
                    )
                    if container_response is not None:
                        buffer = b""
                        yield container_response

                # Tail: emit the remaining buffer if it decrypts
                if buffer:
                    container_response = self._decode_stream_packet(
                        buffer,
                        compression=compression,
                        content_encoding=content_encoding,
                        request_params=request_params,
                        request_raw=request_raw,
                    )
                    if container_response is not None:
                        yield container_response

    def _decode_stream_packet(
        self,
        packet: bytes,
        *,
        compression: Optional[str],
        content_encoding: Optional[str],
        request_params: ContainerRequestParams,
        request_raw: Dict[str, Any],
    ) -> Optional[ContainerResponse]:
        """Decrypt a single streaming chunk (returns None to keep buffering
        when the packet is incomplete or the key mismatches)."""
        try:
            decoded = decode_container_response(
                self.config.key,
                packet_bytes=packet,
                compression=compression,
                content_encoding=content_encoding,
            )
        except Exception:
            return None

        status_code = int(decoded.get("statusCode", 0))
        resp_headers = decoded.get("header", {})
        body_bytes = decoded.get("body", b"")
        if isinstance(body_bytes, str):
            body_bytes = body_bytes.encode("utf-8")

        return ContainerResponse(
            container_success=True,
            container_body={
                "statusCode": status_code,
                "header": resp_headers,
                "body": body_bytes.decode("utf-8", errors="replace"),
            },
            system_error=None,
            status_code=status_code,
            headers=resp_headers,
            body=body_bytes,
            request_params=request_params,
            request_raw=request_raw,
        )
