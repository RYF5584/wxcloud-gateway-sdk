# -*- coding: utf-8 -*-
"""
V3 gateway packet encryption/decryption core.

Implements the full WACloud V3 protocol encryption logic:

- AES-128-CBC encryption/decryption (random IV, transmitted with each packet)
- Snappy (raw block) compression/decompression
- Protobuf encoding/decoding (standard protoc-generated code)
- V3 request packet encoding (JSON and PB appProtocol modes)
- V3 request packet decoding (for debugging)
- V3 response packet decoding

Packet format: ``[2-byte big-endian header length][encrypted header]
[encrypted body]`` where each segment is AES-CBC encrypted with its own
random IV carried at the front of the segment.

Author: RYF5584
    WeChat: RSComapnyCEO
    QQ: 1043695584
    Telegram: ryf5584
    GitHub: https://github.com/RYF5584
"""

from __future__ import annotations

import base64
import json as _json
import os
import secrets
import struct
import time
from typing import Any, Dict, Optional, Tuple, Union

import cramjam
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .wxcloud_pb2 import HTTPHeader, HTTPRequest, HTTPResponse, V3Header

# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

BodyType = Optional[Union[str, bytes]]

# ---------------------------------------------------------------------------
# Snappy compatibility layer
# ---------------------------------------------------------------------------


class _Snappy:
    """Snappy raw block format compression/decompression (via cramjam)."""

    @staticmethod
    def compress(data: bytes) -> bytes:
        return bytes(cramjam.snappy.compress_raw(data))

    @staticmethod
    def decompress(data: bytes) -> bytes:
        return bytes(cramjam.snappy.decompress_raw(data))


snappy = _Snappy()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Default libBuildTs of the V3 protocol (matches WACloud.js)
LIB_BUILD_TS = 1757922934215

#: AES block size
_AES_BLOCK_SIZE = 16

#: V3 gateway path
GATEWAY_PATH = "/__wx__/call"

#: V3 protocol version header
V3_VERSION_HEADER = "3"

#: V3 content type
V3_CONTENT_TYPE = "application/octet-stream"

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _decode_key(key: str) -> bytes:
    """Decode a base64 string key into raw bytes."""
    return base64.b64decode(key)


def _resolve_packet(
    packet_bytes: Optional[bytes],
    packet_b64: Optional[str],
    packet_hex: Optional[str],
) -> bytes:
    """Resolve raw packet bytes from the three input formats (exactly one).

    Args:
        packet_bytes: Raw binary data.
        packet_b64: Base64 encoded string.
        packet_hex: Hex encoded string.

    Returns:
        The decoded raw bytes.

    Raises:
        ValueError: When multiple or no arguments are provided.
    """
    provided = [v for v in (packet_bytes, packet_b64, packet_hex) if v is not None]
    if len(provided) != 1:
        raise ValueError(
            "packet_bytes, packet_b64, packet_hex are mutually exclusive; "
            "pass exactly one"
        )
    if packet_bytes is not None:
        return packet_bytes
    if packet_b64 is not None:
        return base64.b64decode(packet_b64)
    return bytes.fromhex(packet_hex)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# AES-CBC segment encryption/decryption
# ---------------------------------------------------------------------------


def _encrypt_segment(
    key: bytes, plaintext: bytes, iv: Optional[bytes] = None
) -> bytes:
    """AES-CBC encryption; returns IV + ciphertext."""
    iv = iv or os.urandom(_AES_BLOCK_SIZE)
    if len(iv) != _AES_BLOCK_SIZE:
        raise ValueError("iv must be 16 bytes")
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return iv + encryptor.update(padded) + encryptor.finalize()


def _decrypt_segment(key: bytes, segment: bytes) -> bytes:
    """AES-CBC decryption; input is IV + ciphertext."""
    if len(segment) < _AES_BLOCK_SIZE:
        raise ValueError("segment too short: need at least 16 bytes for IV")
    iv = segment[:_AES_BLOCK_SIZE]
    ciphertext = segment[_AES_BLOCK_SIZE:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


# ---------------------------------------------------------------------------
# V3 Header protobuf (standard protoc-generated code)
# ---------------------------------------------------------------------------


def _encode_v3_header(header_meta: Dict[str, Any]) -> bytes:
    """Encode a V3Header protobuf message."""
    msg = V3Header()
    if header_meta.get("encryptionTimestamp") is not None:
        msg.encryptionTimestamp = int(header_meta["encryptionTimestamp"])
    if header_meta.get("compression"):
        msg.compression = str(header_meta["compression"])
    if header_meta.get("userTimeout") is not None:
        msg.userTimeout = int(header_meta["userTimeout"])
    if header_meta.get("libBuildTs") is not None:
        msg.libBuildTs = int(header_meta["libBuildTs"])
    if header_meta.get("appProtocol"):
        msg.appProtocol = str(header_meta["appProtocol"])
    return msg.SerializeToString()


def _decode_v3_header(buffer: bytes) -> Dict[str, Any]:
    """Decode a V3Header protobuf message."""
    msg = V3Header()
    msg.ParseFromString(buffer)
    result: Dict[str, Any] = {}
    # proto3 scalar fields do not support HasField; check non-default values
    if msg.encryptionTimestamp:
        result["encryptionTimestamp"] = msg.encryptionTimestamp
    if msg.compression:
        result["compression"] = msg.compression
    if msg.userTimeout:
        result["userTimeout"] = msg.userTimeout
    if msg.libBuildTs:
        result["libBuildTs"] = msg.libBuildTs
    if msg.appProtocol:
        result["appProtocol"] = msg.appProtocol
    return result


# ---------------------------------------------------------------------------
# V3 packet encoding/decoding
# ---------------------------------------------------------------------------


def _encode_v3_packet(
    key: bytes, header_meta: Dict[str, Any], body_plaintext: bytes
) -> bytes:
    """Encode a V3 packet: [2-byte header length][encrypted header][encrypted body]."""
    header_plaintext = _encode_v3_header(header_meta)
    header_segment = _encrypt_segment(key, header_plaintext)

    compression = header_meta.get("compression") or "snappy"
    if compression == "snappy":
        body_source = snappy.compress(body_plaintext)
    else:
        body_source = body_plaintext

    body_segment = _encrypt_segment(key, body_source)
    return struct.pack(">H", len(header_segment)) + header_segment + body_segment


def _decode_v3_packet(
    key: bytes, packet: bytes
) -> Tuple[Dict[str, Any], bytes]:
    """Decode a V3 packet; returns (header_meta, body_plaintext)."""
    if len(packet) < 2:
        raise ValueError("packet too short: need at least 2 bytes for header length")

    header_length = struct.unpack(">H", packet[:2])[0]
    header_end = 2 + header_length
    if header_end > len(packet):
        raise ValueError(
            "packet header length {} exceeds packet size {}".format(
                header_length, len(packet)
            )
        )

    header_segment = packet[2:header_end]
    body_segment = packet[header_end:]

    header_plain = _decrypt_segment(key, header_segment)
    header_meta = _decode_v3_header(header_plain)

    body_encrypted = _decrypt_segment(key, body_segment)
    compression = header_meta.get("compression")
    if compression == "snappy":
        body_plaintext = snappy.decompress(body_encrypted)
    else:
        # When the compression field is absent/empty, the body is uncompressed
        body_plaintext = body_encrypted

    return header_meta, body_plaintext


# ---------------------------------------------------------------------------
# Body serialization
# ---------------------------------------------------------------------------


def _resolve_body_str(
    data: Optional[Dict[str, Any]],
    json_body: Optional[Dict[str, Any]],
    raw_body: BodyType,
) -> Optional[str]:
    """Serialize data/json/body into a body string."""
    provided = [v for v in (data, json_body, raw_body) if v is not None]
    if len(provided) > 1:
        raise ValueError("data, json, body are mutually exclusive; pass at most one")
    if json_body is not None:
        return _json.dumps(json_body, ensure_ascii=False)
    if data is not None:
        return _json.dumps(data, ensure_ascii=False)
    if isinstance(raw_body, str):
        return raw_body
    if isinstance(raw_body, bytes):
        return raw_body.decode("utf-8", errors="replace")
    return None


# ---------------------------------------------------------------------------
# HTTPHeader list construction
# ---------------------------------------------------------------------------


def _build_header_list(headers: Optional[Dict[str, Any]]) -> list:
    """Convert a dict into a list of HTTPHeader protobuf messages."""
    result = []
    for k, v in (headers or {}).items():
        if k and v is not None:
            h = HTTPHeader()
            h.key = str(k).lower()
            h.value = str(v)
            result.append(h)
    return result


def _header_list_to_dict(header_list: list) -> Dict[str, str]:
    """Convert a list of HTTPHeader messages into a dict."""
    result: Dict[str, str] = {}
    for h in header_list:
        if h.key:
            result[h.key] = h.value
    return result


# ---------------------------------------------------------------------------
# Request packet encoding
# ---------------------------------------------------------------------------


def encode_request(
    key: str,
    method: str,
    headers: Optional[Dict[str, Any]] = None,
    *,
    data: Optional[Dict[str, Any]] = None,
    json: Optional[Dict[str, Any]] = None,  # noqa: A002
    body: BodyType = None,
) -> bytes:
    """Encrypt a V3 request; returns the binary packet.

    Args:
        key: AES key (base64 string).
        method: HTTP method (GET/POST etc.).
        headers: Business request headers.
        data: Form data (mutually exclusive with json/body).
        json: JSON request body (mutually exclusive with data/body).
        body: Raw request body (mutually exclusive with data/json).

    Returns:
        The encrypted V3 binary packet.
    """
    raw_key = _decode_key(key)
    body_str = _resolve_body_str(data, json, body)

    header_meta: Dict[str, Any] = {
        "compression": "snappy",
        "encryptionTimestamp": int(time.time() * 1000),
        "libBuildTs": LIB_BUILD_TS,
        "appProtocol": "1/JSON",
    }

    call_id = "{}-{}".format(int(time.time() * 1000), secrets.token_hex(4))
    header_list = _build_header_list(headers)
    body_json = _json.dumps(
        {
            "body": body_str,
            "call_id": call_id,
            "header": [{"key": h.key, "value": h.value} for h in header_list],
            "method": method,
        },
        ensure_ascii=False,
    )
    return _encode_v3_packet(raw_key, header_meta, body_json.encode("utf-8"))


def encode_request_b64(
    key: str,
    method: str,
    headers: Optional[Dict[str, Any]] = None,
    *,
    data: Optional[Dict[str, Any]] = None,
    json: Optional[Dict[str, Any]] = None,  # noqa: A002
    body: BodyType = None,
) -> str:
    """Encrypt a V3 request; returns a base64 string."""
    packet = encode_request(key, method, headers, data=data, json=json, body=body)
    return base64.b64encode(packet).decode("ascii")


# ---------------------------------------------------------------------------
# Response packet decoding
# ---------------------------------------------------------------------------


def _decode_http_response(body_plaintext: bytes, app_protocol: str) -> Dict[str, Any]:
    """Decode an HTTP response, choosing JSON or PB mode by appProtocol."""
    result: Dict[str, Any] = {
        "statusCode": 0,
        "header": {},
        "body": b"",
    }

    if app_protocol == "1/PB":
        msg = HTTPResponse()
        msg.ParseFromString(body_plaintext)
        result["statusCode"] = msg.statusCode
        result["header"] = _header_list_to_dict(list(msg.header))
        if msg.bodyString:
            result["body"] = msg.bodyString.encode("utf-8")
        elif msg.bodyBuffer:
            result["body"] = bytes(msg.bodyBuffer)
    else:
        try:
            decoded = _json.loads(body_plaintext)
        except (ValueError, UnicodeDecodeError) as e:
            result["body"] = body_plaintext
            result["_decode_error"] = str(e)
            return result

        result["statusCode"] = decoded.get("statusCode", 0)
        headers_list = decoded.get("header", [])
        result["header"] = {
            h.get("key", ""): h.get("value", "")
            for h in headers_list
            if h.get("key")
        }
        body_str = decoded.get("bodyString") or decoded.get("bodyBuffer", "")
        if isinstance(body_str, str):
            result["body"] = body_str.encode("utf-8")
        elif isinstance(body_str, (bytes, bytearray)):
            result["body"] = bytes(body_str)
        else:
            result["body"] = _json.dumps(body_str, ensure_ascii=False).encode(
                "utf-8"
            )

    return result


def decode_response(
    key: str,
    *,
    packet_bytes: Optional[bytes] = None,
    packet_b64: Optional[str] = None,
    packet_hex: Optional[str] = None,
) -> Dict[str, Any]:
    """Decrypt a V3 response packet.

    Args:
        key: AES key (base64 string).
        packet_bytes: The encrypted V3 response packet (binary).
        packet_b64: The encrypted V3 response packet (base64 string).
        packet_hex: The encrypted V3 response packet (hex string).

    Returns:
        A dict with the following fields:

        - ``statusCode``: business HTTP status code
        - ``header``: decrypted response headers dict
        - ``body``: decrypted response body (bytes)
        - ``v3Header``: V3 protocol header info
        - ``_decode_error``: error message when decoding fails (optional)

    Raises:
        ValueError: When packet_bytes/packet_b64/packet_hex are not exactly one.
    """
    raw_key = _decode_key(key)
    packet = _resolve_packet(packet_bytes, packet_b64, packet_hex)
    header_meta, body_plaintext = _decode_v3_packet(raw_key, packet)
    app_protocol = header_meta.get("appProtocol", "1/JSON")
    decoded = _decode_http_response(body_plaintext, app_protocol)
    decoded["v3Header"] = header_meta
    return decoded


# ---------------------------------------------------------------------------
# Request packet decoding (for debugging/verification)
# ---------------------------------------------------------------------------


def decode_request(
    key: str,
    *,
    packet_bytes: Optional[bytes] = None,
    packet_b64: Optional[str] = None,
    packet_hex: Optional[str] = None,
) -> Dict[str, Any]:
    """Decrypt a V3 request packet (for debugging).

    Args:
        key: AES key (base64 string).
        packet_bytes: The encrypted V3 request packet (binary).
        packet_b64: The encrypted V3 request packet (base64 string).
        packet_hex: The encrypted V3 request packet (hex string).

    Returns:
        A dict with ``body`` and ``v3Header``.

    Raises:
        ValueError: When packet_bytes/packet_b64/packet_hex are not exactly one.
    """
    raw_key = _decode_key(key)
    packet = _resolve_packet(packet_bytes, packet_b64, packet_hex)
    header_meta, body_plaintext = _decode_v3_packet(raw_key, packet)
    app_protocol = header_meta.get("appProtocol", "1/JSON")

    if app_protocol == "1/PB":
        msg = HTTPRequest()
        msg.ParseFromString(body_plaintext)
        return {
            "body": {
                "method": msg.method,
                "header": [
                    {"key": h.key, "value": h.value} for h in msg.header
                ],
                "body": bytes(msg.body),
                "callId": msg.callId,
            },
            "v3Header": header_meta,
        }

    try:
        body_json = _json.loads(body_plaintext)
    except (ValueError, UnicodeDecodeError):
        body_json = body_plaintext
    return {"body": body_json, "v3Header": header_meta}
