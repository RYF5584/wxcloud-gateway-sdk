# -*- coding: utf-8 -*-
"""
Cloud Run (callContainer) V1 packet encryption/decryption core.

Implements the full WACloud Cloud Run V1 protocol
(``X-WX-ENCRYPTION-VERSION: 2``) encryption logic:

- AES-128-CBC encryption/decryption (**IV = the key itself**,
  unlike the gateway V3 protocol which uses random IVs)
- Snappy (raw block) compression/decompression
- Protobuf encoding/decoding (HTTPRequest / HTTPResponse / QBaseApiData)
- Request packet encoding (PB and JSON payload modes)
- Request/response packet decoding (for traffic-capture debugging)

Packet format: the entire HTTP body is the ciphertext with no length or IV
prefix, i.e. ``AES-CBC(key, iv=key, snappy.compress(payload))``.
Whether the response is compressed is indicated by the outer HTTP response
header ``x-wx-compression: snappy``; the payload encoding is indicated by
``x-wx-response-content-encoding`` (PB/JSON, default PB).

Author: RYF5584
    WeChat: RSComapnyCEO
    QQ: 1043695584
    Telegram: ryf5584
    GitHub: https://github.com/RYF5584
"""

from __future__ import annotations

import base64
import json as _json
import random
import time
from typing import Any, Dict, Optional, Tuple, Union

import cramjam
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .wxcloud_pb2 import (
    HTTPHeader,
    HTTPRequest,
    HTTPResponse,
    QBaseApiData,
)

# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

BodyType = Optional[Union[str, bytes]]

#: Payload encoding modes
ENCODING_PB = "PB"
ENCODING_JSON = "JSON"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: libBuildTs of the Cloud Run V1 protocol (matches WACloud.js;
#: note this differs from the gateway V3 value)
CONTAINER_LIB_BUILD_TS = 1775716579640

#: Value of the X-WX-ENCRYPTION-VERSION request header
CONTAINER_ENCRYPTION_VERSION = "2"

#: Cloud Run encrypted direct-call path
CONTAINER_SERVICE_PATH = "/wxa-qbase/container_service"

#: Cloud Run streaming (enableChunked) path
CONTAINER_STREAM_PATH = "/wxa-qbase-stream/container_stream"

#: AES block size
_AES_BLOCK_SIZE = 16


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _decode_key(key: str) -> bytes:
    """Decode a base64 string key into raw 16/24/32 bytes."""
    raw = base64.b64decode(key)
    if len(raw) not in (16, 24, 32):
        raise ValueError(
            "Cloud Run key must be a 16/24/32-byte AES key; "
            "decoded {} bytes instead".format(len(raw))
        )
    return raw


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


def _generate_call_id() -> str:
    """Generate a call id matching WACloud format: ``{random}_{ms timestamp}``."""
    return "{}_{}".format(random.random(), int(time.time() * 1000))


# ---------------------------------------------------------------------------
# V1 AES-CBC encryption/decryption (IV = the key itself)
# ---------------------------------------------------------------------------


def _v1_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Cloud Run V1 encryption: AES-CBC with the key as IV and PKCS#7 padding."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(key), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(plaintext) + padder.finalize()
    return encryptor.update(padded) + encryptor.finalize()


def _v1_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """Cloud Run V1 decryption: AES-CBC with the key as IV and PKCS#7 unpadding."""
    if not ciphertext or len(ciphertext) % _AES_BLOCK_SIZE != 0:
        raise ValueError(
            "ciphertext length must be a non-zero multiple of 16 bytes; "
            "got {} bytes".format(len(ciphertext))
        )
    cipher = Cipher(algorithms.AES(key), modes.CBC(key), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def _snappy_compress(data: bytes) -> bytes:
    """Snappy raw block compression (via cramjam)."""
    return bytes(cramjam.snappy.compress_raw(data))


def _snappy_decompress(data: bytes) -> bytes:
    """Snappy raw block decompression (via cramjam)."""
    return bytes(cramjam.snappy.decompress_raw(data))


# ---------------------------------------------------------------------------
# Body serialization
# ---------------------------------------------------------------------------


def _resolve_body_bytes(
    data: Optional[Dict[str, Any]],
    json_body: Optional[Dict[str, Any]],
    raw_body: BodyType,
) -> bytes:
    """Serialize data/json/body into body bytes.

    Args:
        data: Form/JSON data (dict).
        json_body: JSON request body (dict).
        raw_body: Raw request body (str or bytes).

    Returns:
        Body bytes (possibly empty).

    Raises:
        ValueError: When multiple exclusive arguments are provided.
    """
    provided = [v for v in (data, json_body, raw_body) if v is not None]
    if len(provided) > 1:
        raise ValueError("data, json, body are mutually exclusive; pass at most one")
    if json_body is not None:
        return _json.dumps(json_body, ensure_ascii=False).encode("utf-8")
    if data is not None:
        return _json.dumps(data, ensure_ascii=False).encode("utf-8")
    if isinstance(raw_body, str):
        return raw_body.encode("utf-8")
    if isinstance(raw_body, (bytes, bytearray)):
        return bytes(raw_body)
    return b""


# ---------------------------------------------------------------------------
# HTTPHeader list construction
# ---------------------------------------------------------------------------


def _build_header_list(headers: Optional[Dict[str, Any]]) -> list:
    """Convert a dict into a list of HTTPHeader protobuf messages (keys lowercased)."""
    result = []
    for k, v in (headers or {}).items():
        if k and v is not None:
            h = HTTPHeader()
            h.key = str(k).lower()
            h.value = str(v)
            result.append(h)
    return result


def _header_list_to_dict(header_list: list) -> Dict[str, str]:
    """Convert a list of HTTPHeader messages into a dict.

    Repeated headers are joined with a comma, matching WACloud behavior.
    """
    result: Dict[str, str] = {}
    for h in header_list:
        if h.key:
            if h.key in result:
                result[h.key] = "{},{}".format(result[h.key], h.value)
            else:
                result[h.key] = h.value
    return result


# ---------------------------------------------------------------------------
# Request packet encoding
# ---------------------------------------------------------------------------


def encode_container_request(
    key: str,
    method: str,
    headers: Optional[Dict[str, Any]] = None,
    *,
    data: Optional[Dict[str, Any]] = None,
    json: Optional[Dict[str, Any]] = None,  # noqa: A002
    body: BodyType = None,
    encoding: str = ENCODING_PB,
    call_id: Optional[str] = None,
) -> bytes:
    """Encrypt a Cloud Run request; returns the binary HTTP body directly.

    The payload passes through: business serialization -> Snappy compression
    -> AES-128-CBC encryption (IV = key).

    Args:
        key: AES key (base64 string, 16 bytes when decoded).
        method: HTTP method (GET/POST etc.).
        headers: Business request headers (keys are lowercased).
        data: Form data (mutually exclusive with json/body).
        json: JSON request body (mutually exclusive with data/body).
        body: Raw request body (mutually exclusive with data/json).
        encoding: Payload encoding mode, ``"PB"`` (default, HTTP header
            ``X-WX-REQUEST-CONTENT-ENCODING: PB``) or ``"JSON"``.
        call_id: Custom call id; defaults to an auto-generated
            ``{random}_{ms timestamp}``.

    Returns:
        The encrypted binary packet (the entire HTTP body).
    """
    raw_key = _decode_key(key)
    body_bytes = _resolve_body_bytes(data, json, body)
    call_id = call_id or _generate_call_id()
    header_list = _build_header_list(headers)

    if encoding == ENCODING_PB:
        msg = HTTPRequest()
        msg.method = method
        msg.header.extend(header_list)
        msg.body = body_bytes
        msg.callId = call_id
        payload = msg.SerializeToString()
    elif encoding == ENCODING_JSON:
        payload = _json.dumps(
            {
                "method": method,
                "header": [
                    {"key": h.key, "value": h.value} for h in header_list
                ],
                "body": body_bytes.decode("utf-8", errors="replace"),
                "call_id": call_id,
            },
            ensure_ascii=False,
        ).encode("utf-8")
    else:
        raise ValueError("encoding only accepts 'PB' or 'JSON'")

    return _v1_encrypt(raw_key, _snappy_compress(payload))


def encode_container_request_b64(
    key: str,
    method: str,
    headers: Optional[Dict[str, Any]] = None,
    *,
    data: Optional[Dict[str, Any]] = None,
    json: Optional[Dict[str, Any]] = None,  # noqa: A002
    body: BodyType = None,
    encoding: str = ENCODING_PB,
    call_id: Optional[str] = None,
) -> str:
    """Encrypt a Cloud Run request; returns a base64 string.

    Parameters are the same as :func:`encode_container_request`.

    Returns:
        The encrypted packet as a base64 string.
    """
    packet = encode_container_request(
        key, method, headers, data=data, json=json, body=body,
        encoding=encoding, call_id=call_id,
    )
    return base64.b64encode(packet).decode("ascii")


# ---------------------------------------------------------------------------
# Request packet decoding (debugging / traffic capture)
# ---------------------------------------------------------------------------


def decode_container_request(
    key: str,
    *,
    packet_bytes: Optional[bytes] = None,
    packet_b64: Optional[str] = None,
    packet_hex: Optional[str] = None,
    encoding: Optional[str] = None,
    compression: Optional[str] = None,
) -> Dict[str, Any]:
    """Decrypt a Cloud Run request packet (for traffic-capture debugging).

    Args:
        key: AES key (base64 string).
        packet_bytes: The encrypted request packet (binary).
        packet_b64: The encrypted request packet (base64 string).
        packet_hex: The encrypted request packet (hex string).
        encoding: Payload encoding (``"PB"``/``"JSON"``); auto-detected from
            the packet content by default, or pass the captured
            ``X-WX-REQUEST-CONTENT-ENCODING`` header value.
        compression: Compression (``"snappy"`` or empty); auto-detected by
            default, or pass the captured ``X-WX-COMPRESSION`` header value.

    Returns:
        A dict with the following fields (identical structure for PB and
        JSON modes):

        - ``method``: HTTP method
        - ``header``: business request headers dict
        - ``body``: request body (bytes)
        - ``callId``: call id
        - ``encoding``: the actual payload encoding (``"PB"`` or ``"JSON"``)

    Raises:
        ValueError: Wrong key or invalid packet format (PKCS#7 unpadding
            fails on decryption errors).
    """
    raw_key = _decode_key(key)
    packet = _resolve_packet(packet_bytes, packet_b64, packet_hex)
    plaintext = _v1_decrypt(raw_key, packet)

    use_snappy = _resolve_snappy_flag(plaintext, compression)
    if use_snappy:
        plaintext = _snappy_decompress(plaintext)

    resolved_encoding = encoding or _detect_encoding(plaintext)
    if resolved_encoding == ENCODING_PB:
        msg = HTTPRequest()
        msg.ParseFromString(plaintext)
        return {
            "method": msg.method,
            "header": _header_list_to_dict(list(msg.header)),
            "body": bytes(msg.body),
            "callId": msg.callId,
            "encoding": ENCODING_PB,
        }

    payload = _json.loads(plaintext.decode("utf-8"))
    header_list = payload.get("header", [])
    body_data = payload.get("body", "")
    if isinstance(body_data, str):
        body = body_data.encode("utf-8")
    elif isinstance(body_data, (bytes, bytearray)):
        body = bytes(body_data)
    else:
        body = _json.dumps(body_data, ensure_ascii=False).encode("utf-8")
    return {
        "method": payload.get("method", ""),
        "header": {
            h.get("key", ""): h.get("value", "")
            for h in header_list
            if h.get("key")
        },
        "body": body,
        "callId": payload.get("call_id", ""),
        "encoding": ENCODING_JSON,
    }


# ---------------------------------------------------------------------------
# Response packet decoding (core entry point for traffic-capture decryption)
# ---------------------------------------------------------------------------


def _detect_encoding(plaintext: bytes) -> str:
    """Auto-detect the payload encoding (PB or JSON)."""
    stripped = plaintext.lstrip()
    if stripped[:1] in (b"{", b"["):
        return ENCODING_JSON
    return ENCODING_PB


def _resolve_snappy_flag(plaintext: bytes, compression: Optional[str]) -> bool:
    """Resolve the compression flag.

    When ``compression="snappy"`` is passed explicitly it is used directly;
    when omitted, snappy decompression is attempted and failure is treated
    as uncompressed.
    """
    if compression is not None:
        return compression.strip().lower() == "snappy"
    try:
        _snappy_decompress(plaintext)
        return True
    except Exception:
        return False


def _decode_response_payload(
    plaintext: bytes, content_encoding: Optional[str]
) -> Tuple[int, Dict[str, str], bytes]:
    """Decode a response payload; returns (statusCode, header, body)."""
    resolved = content_encoding or _detect_encoding(plaintext)

    if resolved == ENCODING_PB:
        msg = HTTPResponse()
        msg.ParseFromString(plaintext)
        status_code = int(msg.statusCode)
        header = _header_list_to_dict(list(msg.header))
        # Match WACloud: prefer bodyString over bodyBuffer
        if msg.bodyString:
            body = msg.bodyString.encode("utf-8")
        elif msg.bodyBuffer:
            body = bytes(msg.bodyBuffer)
        else:
            body = b""
        return status_code, header, body

    decoded = _json.loads(plaintext.decode("utf-8"))
    status_code = int(decoded.get("statusCode", 0))
    header = {
        h.get("key", ""): h.get("value", "")
        for h in decoded.get("header", [])
        if h.get("key")
    }
    body_data = decoded.get("bodyBuffer") or decoded.get("bodyString") or ""
    if isinstance(body_data, str):
        body = body_data.encode("utf-8")
    else:
        body = _json.dumps(body_data, ensure_ascii=False).encode("utf-8")
    return status_code, header, body


def decode_container_response(
    key: str,
    *,
    packet_bytes: Optional[bytes] = None,
    packet_b64: Optional[str] = None,
    packet_hex: Optional[str] = None,
    compression: Optional[str] = None,
    content_encoding: Optional[str] = None,
) -> Dict[str, Any]:
    """Decrypt a Cloud Run response packet (core capture-decryption entry point).

    Args:
        key: AES key (base64 string).
        packet_bytes: The encrypted response packet (binary, the captured
            HTTP body).
        packet_b64: The encrypted response packet (base64 string).
        packet_hex: The encrypted response packet (hex string).
        compression: Compression; auto-detected from the packet content by
            default, or pass the captured ``x-wx-compression`` header value.
        content_encoding: Payload encoding (``"PB"``/``"JSON"``); auto-detected
            by default, or pass the captured
            ``x-wx-response-content-encoding`` header value.

    Returns:
        A dict with the following fields:

        - ``statusCode``: business HTTP status code
        - ``header``: business response headers dict
        - ``body``: business response body (bytes)
        - ``compression``: the actual compression used (``"snappy"`` or ``""``)
        - ``contentEncoding``: the actual payload encoding (``"PB"``/``"JSON"``)

    Raises:
        ValueError: Wrong key or invalid packet format.
    """
    raw_key = _decode_key(key)
    packet = _resolve_packet(packet_bytes, packet_b64, packet_hex)
    plaintext = _v1_decrypt(raw_key, packet)

    use_snappy = _resolve_snappy_flag(plaintext, compression)
    if use_snappy:
        plaintext = _snappy_decompress(plaintext)

    resolved_encoding = content_encoding or _detect_encoding(plaintext)
    status_code, header, body = _decode_response_payload(plaintext, resolved_encoding)

    return {
        "statusCode": status_code,
        "header": header,
        "body": body,
        "compression": "snappy" if use_snappy else "",
        "contentEncoding": resolved_encoding,
    }


# ---------------------------------------------------------------------------
# stdpriv channel (qbase-level APIs; debugging / traffic capture)
# ---------------------------------------------------------------------------


def encode_std_priv_request(
    key: str,
    qbase_api_name: str,
    qbase_req: str,
    *,
    cli_req_id: Optional[str] = None,
    session_id: str = "",
    sdk_version: str = "",
    filter_user_info: bool = False,
    first_launch: bool = False,
    env: str = "",
    appid: str = "",
    region: str = "",
) -> bytes:
    """Encrypt a Cloud Run stdpriv request (qbase-level APIs such as
    ``tcbapi_get_service_info``).

    The payload is a ``QBaseApiData`` protobuf, also compressed with snappy
    and encrypted with AES-CBC.

    Args:
        key: AES key (base64 string).
        qbase_api_name: qbase API name (e.g. ``tcbapi_get_service_info``).
        qbase_req: Business request JSON string.
        cli_req_id: Client request id; defaults to an auto-generated
            ``{ms timestamp}_{random}``.
        session_id: Session id.
        sdk_version: SDK version identifier.
        filter_user_info: Whether to filter user info.
        first_launch: Whether this is a first launch.
        env: Cloud environment id.
        appid: appid.
        region: Region.

    Returns:
        The encrypted binary packet.
    """
    raw_key = _decode_key(key)
    msg = QBaseApiData()
    msg.qbaseApiName = qbase_api_name
    msg.qbaseReq = qbase_req
    msg.cliReqId = cli_req_id or "{}_{}".format(int(time.time() * 1000), random.random())
    if session_id:
        msg.qbaseMeta.sessionId = session_id
    if sdk_version:
        msg.qbaseMeta.sdkVersion = sdk_version
    if filter_user_info:
        msg.qbaseMeta.filterUserInfo = True
    if first_launch:
        msg.qbaseMeta.firstLaunch = True
    if env:
        msg.qbaseOptions.env = env
    if appid:
        msg.qbaseOptions.appid = appid
    if region:
        msg.qbaseOptions.region = region
    return _v1_encrypt(raw_key, _snappy_compress(msg.SerializeToString()))


def decode_std_priv_response(
    key: str,
    *,
    packet_bytes: Optional[bytes] = None,
    packet_b64: Optional[str] = None,
    packet_hex: Optional[str] = None,
    compression: Optional[str] = None,
) -> Dict[str, Any]:
    """Decrypt a Cloud Run stdpriv response packet (JSON text payload;
    for traffic-capture debugging).

    Args:
        key: AES key (base64 string).
        packet_bytes: The encrypted response packet (binary).
        packet_b64: The encrypted response packet (base64 string).
        packet_hex: The encrypted response packet (hex string).
        compression: Compression; auto-detected by default.

    Returns:
        The decrypted JSON dict.

    Raises:
        ValueError: Wrong key or invalid packet format.
    """
    raw_key = _decode_key(key)
    packet = _resolve_packet(packet_bytes, packet_b64, packet_hex)
    plaintext = _v1_decrypt(raw_key, packet)

    use_snappy = _resolve_snappy_flag(plaintext, compression)
    if use_snappy:
        plaintext = _snappy_decompress(plaintext)

    return _json.loads(plaintext.decode("utf-8"))
