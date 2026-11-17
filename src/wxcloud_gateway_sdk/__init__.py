# -*- coding: utf-8 -*-
"""
wxcloud-gateway-sdk: WeChat Cloud Gateway V3 + Cloud Run request SDK

- Cloud Gateway V3: ``/__wx__/call`` channel, AES-CBC with random IV +
  2-byte length prefix + Snappy + PB
- Cloud Run: ``/wxa-qbase/container_service`` channel
  (``X-WX-ENCRYPTION-VERSION: 2``), AES-CBC (IV = key) + Snappy + PB/JSON

Author: RYF5584
    WeChat: RSComapnyCEO
    QQ: 1043695584
    Telegram: ryf5584
    GitHub: https://github.com/RYF5584
"""

from __future__ import annotations

from .async_client import AiohttpHttpOptions, GatewayAsyncClient
from .codec import (
    decode_request,
    decode_response,
    encode_request,
    encode_request_b64,
)
from .container_async_client import ContainerAsyncClient, ContainerAsyncHttpOptions
from .container_codec import (
    decode_container_request,
    decode_container_response,
    decode_std_priv_response,
    encode_container_request,
    encode_container_request_b64,
    encode_std_priv_request,
)
from .container_models import (
    ContainerConfig,
    ContainerRequestParams,
    ContainerResponse,
)
from .container_sync_client import ContainerHttpOptions, ContainerSyncClient
from .models import GatewayConfig, GatewayRequestParams, GatewayResponse, RawHttpResponse
from .sync_client import GatewaySyncClient, RequestsHttpOptions

__version__ = "1.0.0"

__author__ = "RYF5584"
__all__ = [
    # Config & models (gateway)
    "GatewayConfig",
    "GatewayRequestParams",
    "GatewayResponse",
    "RawHttpResponse",
    # Config & models (Cloud Run)
    "ContainerConfig",
    "ContainerRequestParams",
    "ContainerResponse",
    # Clients (gateway)
    "GatewaySyncClient",
    "GatewayAsyncClient",
    "RequestsHttpOptions",
    "AiohttpHttpOptions",
    # Clients (Cloud Run)
    "ContainerSyncClient",
    "ContainerAsyncClient",
    "ContainerHttpOptions",
    "ContainerAsyncHttpOptions",
    # Encryption/decryption functions (gateway)
    "encode_request",
    "encode_request_b64",
    "decode_request",
    "decode_response",
    # Encryption/decryption functions (Cloud Run)
    "encode_container_request",
    "encode_container_request_b64",
    "decode_container_request",
    "decode_container_response",
    # stdpriv channel (Cloud Run qbase-level APIs; debugging)
    "encode_std_priv_request",
    "decode_std_priv_response",
]
