# -*- coding: utf-8 -*-
"""
Protobuf varint encoding/decoding utilities.

Used only for lightweight parsing of the V3 header in JSON mode.
Standard protobuf message encoding is handled by ``wxcloud_pb2.py``
(protoc generated).

Author: RYF5584
    WeChat: RSComapnyCEO
    QQ: 1043695584
    Telegram: ryf5584
    GitHub: https://github.com/RYF5584
"""

from __future__ import annotations

from typing import Tuple


def encode_varint(value: int) -> bytes:
    """Encode a non-negative integer as a protobuf varint."""
    if value < 0:
        raise ValueError("varint only supports non-negative integers")
    parts = bytearray()
    while True:
        chunk = value & 0x7F
        value >>= 7
        if value:
            parts.append(chunk | 0x80)
        else:
            parts.append(chunk)
            return bytes(parts)


def decode_varint(buffer: bytes, offset: int = 0) -> Tuple[int, int]:
    """Decode a varint from buffer at offset; returns (value, new_offset)."""
    result = 0
    shift = 0
    while offset < len(buffer):
        byte = buffer[offset]
        result |= (byte & 0x7F) << shift
        offset += 1
        if not (byte & 0x80):
            return result, offset
        shift += 7
    raise ValueError("unterminated varint")


def read_length_delimited(buffer: bytes, offset: int) -> Tuple[bytes, int]:
    """Read a length-delimited field; returns (data, new_offset)."""
    length, offset = decode_varint(buffer, offset)
    return buffer[offset : offset + length], offset + length


def skip_unknown_field(buffer: bytes, offset: int, wire_type: int) -> int:
    """Skip an unknown field; returns the new offset."""
    if wire_type == 0:
        _, offset = decode_varint(buffer, offset)
        return offset
    if wire_type == 1:
        return offset + 8
    if wire_type == 2:
        length, offset = decode_varint(buffer, offset)
        return offset + length
    if wire_type == 5:
        return offset + 4
    return offset + 1
