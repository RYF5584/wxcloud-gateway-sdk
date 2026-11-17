<div align="center">

# wxcloud-gateway-sdk

**微信云网关 V3 / 云托管 加密请求 SDK**

[![PyPI Version](https://img.shields.io/pypi/v/wxcloud-gateway-sdk?style=flat&logo=pypi&logoColor=white)](https://pypi.org/project/wxcloud-gateway-sdk/)
[![Python Versions](https://img.shields.io/pypi/pyversions/wxcloud-gateway-sdk?style=flat&logo=python&logoColor=white)](https://pypi.org/project/wxcloud-gateway-sdk/)
[![Downloads](https://img.shields.io/pypi/dm/wxcloud-gateway-sdk?style=flat&color=blue)](https://pypi.org/project/wxcloud-gateway-sdk/)
[![GitHub Stars](https://img.shields.io/github/stars/RYF5584/wxcloud-gateway-sdk?style=flat&logo=github)](https://github.com/RYF5584/wxcloud-gateway-sdk/stargazers)
[![License](https://img.shields.io/github/license/RYF5584/wxcloud-gateway-sdk?style=flat)](LICENSE)

</div>

## ✨ 特性

- ☁️ 支持微信云网关 V3（`/__wx__/call`）与云托管 Cloud Run（`/wxa-qbase/container_service`）
- 🔐 自动处理 AES-CBC 加解密、Snappy 压缩、Protobuf 编解码
- ⚡ 同步（requests）与异步（aiohttp）双客户端
- 🧩 `get` / `post` / `put` / `patch` / `delete` 快捷方法
- 🔀 云托管多环境 / 多服务，支持按请求切换
- 📡 云托管流式响应，逐块解密
- 🔎 内置独立解密函数，抓包数据直接解密
- 🐍 Python 3.8+，Windows / macOS / Linux 全平台

## 📦 安装

**pip**

```bash
pip install wxcloud-gateway-sdk
```

**uv**

```bash
uv add wxcloud-gateway-sdk
```

## 🚀 快速开始

### 云网关 V3

```python
from wxcloud_gateway_sdk import GatewaySyncClient

client = GatewaySyncClient(
    key="your-base64-key",
    domain="xxx.wxgateway.com",
    token="105_xxx",
)

resp = client.post("/api/v1/data", json={"page": 1})

print(resp.status_code)  # 业务 HTTP 状态码
print(resp.headers)      # 解密后的响应头
print(resp.json())       # JSON 反序列化
```

### 异步客户端

```python
import asyncio
from wxcloud_gateway_sdk import GatewayAsyncClient

async def main():
    client = GatewayAsyncClient(
        key="your-base64-key",
        domain="xxx.wxgateway.com",
        token="105_xxx",
    )
    resp = await client.post("/api/v1/data", json={"page": 1})
    print(resp.json())

asyncio.run(main())
```

### 云托管

```python
from wxcloud_gateway_sdk import ContainerSyncClient

client = ContainerSyncClient(
    key="your-base64-key",
    url="https://xxxservicewechat.com/wxa-qbase/container_service?token=xxx",
    timestamp="1775716579640",
    env="your-env-id",
    service="your-service-name",
)

resp = client.post("/api/v1/data", json={"page": 1})
print(resp.json())

# env / service / user_timeout 支持按请求覆盖
resp = client.post("/api/v1/data", json={"page": 1}, env="other-env", service="other-service")
```

### 云托管流式响应

```python
import asyncio
from wxcloud_gateway_sdk import ContainerAsyncClient

async def main():
    client = ContainerAsyncClient(key="...", url="...", env="...", service="...")

    async for chunk in client.send_stream_request("POST", "/api/chat", json={"q": "你好"}):
        print(chunk.body.decode("utf-8"), end="", flush=True)

asyncio.run(main())
```

### 抓包解密

```python
from wxcloud_gateway_sdk import decode_response, decode_container_request, decode_container_response

# 云网关响应
data = decode_response(key, packet_b64="抓包body的base64")
print(data["statusCode"], data["header"], data["body"])

# 云托管请求
data = decode_container_request(key, packet_b64="抓包body的base64")
print(data["method"], data["header"], data["body"])

# 云托管响应
data = decode_container_response(key, packet_b64="抓包body的base64")
print(data["statusCode"], data["header"], data["body"])
```

支持 `packet_bytes` / `packet_b64` / `packet_hex` 三种输入。

## 📋 响应对象

| 属性 | 说明 |
|---|---|
| `status_code` | 业务 HTTP 状态码 |
| `headers` | 解密后的响应头 |
| `body` | 解密后的响应 body（bytes） |
| `json()` | JSON 反序列化 |
| `call_id` | 本次调用 id（云托管） |
| `token_expired` | 凭据是否过期（云托管） |
| `raw_http` | 原始 HTTP 响应（调试用） |

## 👤 作者

**RYF5584**

- QQ: [1043695584](https://qm.qq.com/q/1043695584)
- WeChat: RSComapnyCEO
- Telegram: [@ryf5584](https://t.me/ryf5584)
- GitHub: [RYF5584](https://github.com/RYF5584)

## 📄 License

[MIT](LICENSE)
