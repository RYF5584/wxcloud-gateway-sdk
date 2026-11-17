# -*- coding: utf-8 -*-
"""
Shared Cloud Run client internals (used by sync/async/streaming clients).

Pure logic only: body serialization, response decryption wrapper, system
error parsing, redirect detection. Contains no transport-layer code so all
client variants share one consistent behavior.

Author: RYF5584
    WeChat: RSComapnyCEO
    QQ: 1043695584
    Telegram: ryf5584
    GitHub: https://github.com/RYF5584
"""

from __future__ import annotations

import json as _json
from typing import Any, Dict, Optional, Union

from .container_codec import decode_container_response
from .container_models import (
    ContainerRequestParams,
    ContainerResponse,
)
from .models import RawHttpResponse


def resolve_body_bytes(
    data: Optional[Dict[str, Any]],
    json: Optional[Dict[str, Any]],  # noqa: A002
    body: Optional[Union[str, bytes]],
) -> bytes:
    """Serialize data/json/body into request body bytes (mutually exclusive)."""
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


def get_header(headers: Dict[str, str], name: str) -> str:
    """Look up a response header case-insensitively; empty string if absent."""
    name_lower = name.lower()
    for k, v in (headers or {}).items():
        if k.lower() == name_lower:
            return v
    return ""


def parse_system_error(headers: Dict[str, str]) -> Optional[int]:
    """Parse the outer response header ``x-wx-system-error``; None if absent."""
    value = get_header(headers, "x-wx-system-error")
    if not value:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _body_to_bytes(body_data: Any) -> bytes:
    """Convert a decoded body field into bytes uniformly."""
    if isinstance(body_data, str):
        return body_data.encode("utf-8")
    if isinstance(body_data, (bytes, bytearray)):
        return bytes(body_data)
    return _json.dumps(body_data, ensure_ascii=False).encode("utf-8")


def build_response(
    key: str,
    http_status: int,
    http_headers: Dict[str, str],
    http_body: bytes,
    request_params: ContainerRequestParams,
    request_raw: Dict[str, Any],
) -> ContainerResponse:
    """Build a :class:`ContainerResponse` from the raw HTTP response
    (decrypt + system error detection).

    Decryption failure (e.g. key mismatch) does not raise: it produces
    ``container_success=False`` and ``container_body={"raw": ...}`` so the
    problem can be investigated via ``raw_http``.
    """
    raw_http = RawHttpResponse(
        status_code=http_status, headers=dict(http_headers), body=http_body
    )
    system_error = parse_system_error(http_headers)

    if http_body:
        try:
            decoded = decode_container_response(
                key,
                packet_bytes=http_body,
                compression=get_header(http_headers, "x-wx-compression") or None,
                content_encoding=(
                    get_header(http_headers, "x-wx-response-content-encoding") or None
                ),
            )
            status_code = int(decoded.get("statusCode", 0))
            resp_headers = decoded.get("header", {})
            body_bytes = _body_to_bytes(decoded.get("body", b""))

            container_body_dict: Dict[str, Any] = {
                "statusCode": status_code,
                "header": resp_headers,
                "body": body_bytes.decode("utf-8", errors="replace"),
            }

            if status_code > 0 and system_error is None:
                # The container service responded (404/500 still counts as success)
                return ContainerResponse(
                    container_success=True,
                    container_body=container_body_dict,
                    system_error=system_error,
                    raw_http=raw_http,
                    status_code=status_code,
                    headers=resp_headers,
                    body=body_bytes,
                    request_params=request_params,
                    request_raw=request_raw,
                )
            # Cloud Run itself returned a system error; the container was not reached
        except Exception:
            # Decryption failed (e.g. key mismatch)
            pass

    return ContainerResponse(
        container_success=False,
        container_body={"raw": http_body},
        system_error=system_error,
        raw_http=raw_http,
        status_code=0,
        headers={},
        body=b"",
        request_params=request_params,
        request_raw=request_raw,
    )


def find_redirect_location(response: ContainerResponse) -> str:
    """Extract the redirect Location from the decrypted business response
    (for 3xx); empty string when there is none."""
    if not response.container_success:
        return ""
    if not (300 <= response.status_code < 400):
        return ""
    return get_header(response.headers, "location")


def build_plain_response(
    http_status: int,
    http_headers: Dict[str, str],
    http_body: bytes,
    request_params: ContainerRequestParams,
    request_raw: Dict[str, Any],
) -> ContainerResponse:
    """Build a :class:`ContainerResponse` from a plaintext-forwarded HTTP
    response (absolute-URL redirects).

    Absolute-URL redirects go over plaintext HTTP per WACloud behavior; the
    response is not decrypted again and ``container_body`` records the
    plaintext response content.
    """
    raw_http = RawHttpResponse(
        status_code=http_status, headers=dict(http_headers), body=http_body
    )
    system_error = parse_system_error(http_headers)
    success = http_status > 0 and system_error is None
    body_bytes = http_body
    return ContainerResponse(
        container_success=success,
        container_body={
            "statusCode": http_status,
            "header": dict(http_headers),
            "body": http_body.decode("utf-8", errors="replace"),
        },
        system_error=system_error,
        raw_http=raw_http,
        status_code=http_status if success else 0,
        headers=dict(http_headers) if success else {},
        body=body_bytes if success else b"",
        request_params=request_params,
        request_raw=request_raw,
    )
