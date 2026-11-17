# -*- coding: utf-8 -*-
"""
Synchronous client (based on requests).

Author: RYF5584
    WeChat: RSComapnyCEO
    QQ: 1043695584
    Telegram: ryf5584
    GitHub: https://github.com/RYF5584
"""

from __future__ import annotations

import json as _json
import warnings as _warnings
from typing import Any, Dict, Optional, Tuple, TypedDict, Union

import requests

try:
    from urllib3.exceptions import InsecureRequestWarning
    _warnings.filterwarnings("ignore", category=InsecureRequestWarning)
except Exception:  # pragma: no cover
    pass

from .codec import decode_response
from .models import GatewayConfig, GatewayRequestParams, GatewayResponse, RawHttpResponse


class RequestsHttpOptions(TypedDict, total=False):
    """Native requests options.

    Passed through to ``requests.request()``; commonly used options below.
    """

    timeout: float
    proxies: Dict[str, str]
    verify: Union[bool, str]
    cert: Union[str, Tuple[str, str]]
    auth: Tuple[str, str]
    cookies: Dict[str, str]
    allow_redirects: bool


class GatewaySyncClient:
    """V3 gateway synchronous client (based on requests).

    Pass key/domain/token/rid at init time, then call send_request (or the
    get/post convenience methods) like a plain HTTP client; gateway
    encryption/decryption/routing is handled automatically.
    """

    def __init__(
        self,
        key: str,
        domain: str,
        *,
        token: str = "",
        rid: str = "",
        referer: str = "",
        user_agent: str = "",
        origin_base_url: str = "",
        wx_conf_version: str = "1765020855",
        wx_target_service: str = "HTTP",
        wx_http_mode: str = "REROUTE",
    ):
        """Initialize the client.

        Args:
            key: AES key (base64 string).
            domain: Gateway domain.
            token: Access token.
            rid: Request ID (issued by the server).
            referer: HTTP referer header.
            user_agent: HTTP User-Agent header.
            origin_base_url: Base URL of the business server (e.g.
                https://example.com). Relative paths passed to send_request
                are joined with it automatically; slashes are handled.
            wx_conf_version: Gateway config version.
            wx_target_service: x-wx-target-service header (default HTTP).
            wx_http_mode: x-wx-http-mode header (default REROUTE).
        """
        self.config = GatewayConfig(
            key=key,
            domain=domain,
            token=token,
            rid=rid,
            referer=referer,
            user_agent=user_agent,
            origin_base_url=origin_base_url,
            wx_conf_version=wx_conf_version,
            wx_target_service=wx_target_service,
            wx_http_mode=wx_http_mode,
        )

    def send_request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, Any]] = None,
        query: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,  # noqa: A002
        body: Optional[Union[str, bytes]] = None,
        **http_options: Any,
    ) -> GatewayResponse:
        """Send an encrypted request and return the decrypted response.

        Pass method, url and business headers like a plain HTTP client;
        gateway encryption and routing parameters are injected automatically.

        Args:
            method: HTTP method (GET/POST etc.).
            url: Request path (e.g. /api/v1/data).
            headers: Business request headers (e.g. authorization, content-type).
            query: URL query parameters.
            data: Form data (mutually exclusive with json/body).
            json: JSON request body (mutually exclusive with data/body).
            body: Raw request body (mutually exclusive with data/json).
            **http_options: Native requests options (see :class:`RequestsHttpOptions`).

        Returns:
            The decrypted :class:`GatewayResponse`; ``status_code``/``headers``/
            ``body`` hold the business server's values.
        """
        body_bytes = self._resolve_body_bytes(data, json, body)

        request_params = GatewayRequestParams(
            config=self.config,
            method=method,
            url=url,
            headers=headers or {},
            body=body_bytes,
            query=query or {},
        )

        request_raw = request_params.encrypt()

        # Empty UA/Referer when unset, preventing requests from injecting its own
        final_headers = dict(request_raw["headers"])
        if "User-Agent" not in final_headers:
            final_headers["User-Agent"] = ""
        if "Referer" not in final_headers:
            final_headers["Referer"] = ""

        response = requests.request(
            method=request_raw["method"],
            url=request_raw["url"],
            data=request_raw["body"],
            headers=final_headers,
            **http_options,
        )

        raw_http = RawHttpResponse(
            status_code=response.status_code,
            headers=dict(response.headers),
            body=response.content,
        )

        if response.content and len(response.content) > 2:
            try:
                decoded = decode_response(
                    self.config.key, packet_bytes=response.content
                )
                status_code = decoded.get("statusCode", 0)
                resp_headers = decoded.get("header", {})
                body_data = decoded.get("body", b"")
                if isinstance(body_data, str):
                    body_bytes_resp = body_data.encode("utf-8")
                elif isinstance(body_data, (bytes, bytearray)):
                    body_bytes_resp = bytes(body_data)
                else:
                    body_bytes_resp = _json.dumps(
                        body_data, ensure_ascii=False
                    ).encode("utf-8")

                # gateway_body: the full decrypted gateway structure
                gateway_body_dict: Dict[str, Any] = {
                    "statusCode": status_code,
                    "header": resp_headers,
                    "body": body_bytes_resp.decode("utf-8", errors="replace"),
                }

                if status_code > 0 and not resp_headers.get("x-wx-system-error"):
                    # The business server responded (404/500 still counts as success)
                    gateway_success = True
                else:
                    # The gateway itself returned an error (e.g. -601001);
                    # business fields are cleared so no error plaintext leaks
                    gateway_success = False
                    status_code = 0
                    resp_headers = {}
                    body_bytes_resp = b""
            except Exception:
                # Gateway decryption failed
                gateway_success = False
                gateway_body_dict = {"raw": response.content}
                status_code = 0
                resp_headers = {}
                body_bytes_resp = b""
        else:
            gateway_success = False
            gateway_body_dict = {"raw": response.content}
            status_code = 0
            resp_headers = {}
            body_bytes_resp = b""

        return GatewayResponse(
            gateway_success=gateway_success,
            gateway_body=gateway_body_dict,
            raw_http=raw_http,
            status_code=status_code,
            headers=resp_headers,
            body=body_bytes_resp,
            request_params=request_params,
            request_raw=request_raw,
        )

    # ------------------------------------------------------------------
    # Convenience methods by request type
    # ------------------------------------------------------------------

    def get(
        self,
        url: str,
        *,
        headers: Optional[Dict[str, Any]] = None,
        query: Optional[Dict[str, Any]] = None,
        **http_options: Any,
    ) -> GatewayResponse:
        """Send a GET request.

        Args:
            url: Request path (set origin_base_url for relative paths).
            headers: Business request headers.
            query: URL query parameters.
            **http_options: Native requests options (see :class:`RequestsHttpOptions`).

        Returns:
            The decrypted :class:`GatewayResponse`.
        """
        return self.send_request("GET", url, headers=headers, query=query, **http_options)

    def post(
        self,
        url: str,
        *,
        headers: Optional[Dict[str, Any]] = None,
        query: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,  # noqa: A002
        body: Optional[Union[str, bytes]] = None,
        **http_options: Any,
    ) -> GatewayResponse:
        """Send a POST request.

        Args:
            url: Request path.
            headers: Business request headers.
            query: URL query parameters.
            data: Form data (mutually exclusive with json/body).
            json: JSON request body (mutually exclusive with data/body).
            body: Raw request body (mutually exclusive with data/json).
            **http_options: Native requests options.

        Returns:
            The decrypted :class:`GatewayResponse`.
        """
        return self.send_request(
            "POST", url, headers=headers, query=query, data=data, json=json,
            body=body, **http_options,
        )

    def put(
        self,
        url: str,
        *,
        headers: Optional[Dict[str, Any]] = None,
        query: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,  # noqa: A002
        body: Optional[Union[str, bytes]] = None,
        **http_options: Any,
    ) -> GatewayResponse:
        """Send a PUT request. Same parameters as :meth:`post`."""
        return self.send_request(
            "PUT", url, headers=headers, query=query, data=data, json=json,
            body=body, **http_options,
        )

    def patch(
        self,
        url: str,
        *,
        headers: Optional[Dict[str, Any]] = None,
        query: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,  # noqa: A002
        body: Optional[Union[str, bytes]] = None,
        **http_options: Any,
    ) -> GatewayResponse:
        """Send a PATCH request. Same parameters as :meth:`post`."""
        return self.send_request(
            "PATCH", url, headers=headers, query=query, data=data, json=json,
            body=body, **http_options,
        )

    def delete(
        self,
        url: str,
        *,
        headers: Optional[Dict[str, Any]] = None,
        query: Optional[Dict[str, Any]] = None,
        **http_options: Any,
    ) -> GatewayResponse:
        """Send a DELETE request.

        Args:
            url: Request path.
            headers: Business request headers.
            query: URL query parameters.
            **http_options: Native requests options.

        Returns:
            The decrypted :class:`GatewayResponse`.
        """
        return self.send_request("DELETE", url, headers=headers, query=query, **http_options)

    @staticmethod
    def _resolve_body_bytes(
        data: Optional[Dict[str, Any]],
        json: Optional[Dict[str, Any]],  # noqa: A002
        body: Optional[Union[str, bytes]],
    ) -> bytes:
        provided = [v for v in (data, json, body) if v is not None]
        if len(provided) > 1:
            raise ValueError("data, json, body are mutually exclusive; pass at most one")
        if json is not None:
            return _json.dumps(json, ensure_ascii=False).encode("utf-8")
        if data is not None:
            return _json.dumps(data, ensure_ascii=False).encode("utf-8")
        if isinstance(body, str):
            return body.encode("utf-8")
        if isinstance(body, (bytes, bytearray)):
            return bytes(body)
        return b""
