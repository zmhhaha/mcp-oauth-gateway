# mcp-oauth-gateway

**把 OAuth 2.1 带给那些"只会发一个静态 `Authorization` 头"的 MCP 客户端。**

不少 MCP 客户端无法连接实现了规范授权流程的 MCP 服务器：它们只发一个固定头、不做发现、也不
处理 `401` 挑战，于是服务器**根本连不上**，报错五花八门：

```
Error POSTing to endpoint: {"error":{"code":-32001,"message":"Bearer token required"}}
Server status: needs-auth
SDK auth failed: Dynamic Client Registration rejected (HTTP 400):
  {"error":"invalid_client_metadata","error_description":"dynamic client registration is disabled..."}
```

手工贴一把长期 JWT 进客户端配置"能用"，但很快会烂掉：token 会过期、明文散落在多个配置文件里、
每个客户端各存一份。

这个网关跑在本机回环地址上，**替客户端持有凭据**：

```
        静态头                          自动续期的 OAuth 2.1
客户端 ─────────────▶ 127.0.0.1:33419/mcp ──────────────────▶ 你的 MCP 服务器
                            │
                            └── 完成 RFC 9728 发现、PKCE 与静默续期；
                                凭据存在系统配置目录（0600），不进客户端配置
```

客户端始终访问本机地址，用的是**一个稳定、且不是 OAuth 凭据的本地令牌** —— 所以 OAuth token
怎么轮转，客户端的配置文件都不用动。

**零依赖，只要 Node ≥ 20**（用内置 `fetch` / `node:http` / `node:test`）。

## 它在协议上做了什么

1. `POST <mcp-url>` → 读 `401` 及其 `WWW-Authenticate` 挑战头；
2. 拉取挑战头指向的 **Protected Resource Metadata**（RFC 9728）；
3. 拉取授权服务器元数据（RFC 8414，回退到 `openid-configuration`）；
4. **如果服务器允许**就做动态客户端注册（RFC 7591）；不允许则明确告诉你该怎么手工配置；
5. 打开浏览器走**授权码 + PKCE(S256)**，并带上 `resource=<mcp-url>`（RFC 8707），
   让 token 的 audience 绑定到你这台服务器；
6. 存下 access/refresh token，并在过期前静默续期。

**不与任何厂商绑定**：只要 MCP 服务器发布了 protected-resource metadata、授权服务器支持
PKCE，就能用。

## 快速开始

```bash
git clone https://github.com/zmhhaha/mcp-oauth-gateway
cd mcp-oauth-gateway

# 1) 授权一次（会打开浏览器；凭据存在仓库之外）
node bin/mcp-oauth-gateway.mjs login --url https://your-mcp-host/mcp

# 2) 启动网关
node bin/mcp-oauth-gateway.mjs serve --url https://your-mcp-host/mcp --port 33419

# 3) 打印可直接粘贴的客户端配置
node bin/mcp-oauth-gateway.mjs print-config --url https://your-mcp-host/mcp
```

若你的授权服务器不提供动态注册，`login` 时加 `--client-id <id>`；报错信息会告诉你该登记哪个
回调地址。

## 怎么接到客户端

### DSH（DeepSeek Harness）

DSH 的 MCP 客户端**完全不支持 OAuth**，所以这就是它的主场。

**这个仓库本身就是那个 DSH bundle**（根 `package.json` 声明了 `dsh.bundle.patch`），所以 Plugins
面板可以直接用本仓库的 Git 地址或本地路径安装。（DSH **没有可浏览的插件市场**：它只接受 npm 包名、
Git 仓库地址、压缩包或本地路径，界面里另外只列 DSH 自带的官方插件。按包名安装需要先把本包发到 npm，
目前**尚未发布**。）

`print-config` 给出的两个值怎么填、以及注意事项，见 [`dsh/README.md`](dsh/README.md)。

### 任何支持自定义头的客户端

```json
{
  "mcpServers": {
    "your-server": {
      "type": "http",
      "url": "http://127.0.0.1:33419/mcp",
      "headers": { "x-mcp-gateway-token": "<来自 print-config>" }
    }
  }
}
```

### curl

```bash
curl -sS -X POST http://127.0.0.1:33419/mcp \
  -H "x-mcp-gateway-token: <来自 print-config>" \
  -H 'content-type: application/json' \
  -H 'accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}'
```

**自己就能走 OAuth 的客户端**（Claude Code、开了实验开关的 Codex）请继续用它们自己的流程 ——
这个网关是给走不了的那些用的。

## 命令

| 命令 | 作用 |
|---|---|
| `login --url <mcp-url>` | 交互式授权，存下 access + refresh token |
| `serve --url <mcp-url>` | 启动回环网关，直到被中断 |
| `status --url <mcp-url>` | 查看凭据状态（**从不打印 token 本身**） |
| `refresh --url <mcp-url>` | 立即强制续期（适合放进计划任务） |
| `print-config --url <mcp-url>` | 打印 DSH / JSON 客户端 / curl 的配置 |
| `logout --url <mcp-url>` | 删除已存凭据 |

| 选项 | 含义 |
|---|---|
| `--client-id <id>` | 跳过动态注册，直接用这个 client id |
| `--port <n>` | 回环端口（默认 `33419`） |
| `--redirect-host <h>` | 回调 URI 里的主机名（默认 `localhost`） |
| `--scope <list>` | 空格或逗号分隔的 scope（默认 `openid,email,profile`） |
| `--auth-server <url>` | 服务器没有 RFC 9728 挑战头时，手工指定 issuer |
| `--store <dir>` | 状态目录（默认系统配置目录） |
| `--no-open` | 不尝试打开浏览器，只打印 URL |

## 安全与限制

- **只监听回环。** 同时绑 `127.0.0.1` 与 `::1`（因为 `localhost` 可能解析到任一个 —— 这里不
  一致就会把浏览器回调搞坏）。没有本地令牌的请求一律拒绝。
- **本地令牌不是 OAuth 凭据。** 它稳定、可以放进客户端配置；OAuth token 只留在网关的状态文件
  里（系统配置目录下，`0600`），从不进入客户端配置。
- **同用户的其他进程可以读那个状态文件。** 网关令牌对"以你身份运行的一切"可见 —— 与任何本地
  开发工具是同一条信任边界。别在共享机器上用共享账号跑它。
- **一个进程一个上游**，同一时刻只处理一次登录，状态在内存里。多个 MCP 服务器就起多个网关
  （各占一个端口）。
- **让它一直跑着。** 只有网关在运行时才会续期；refresh token 在授权服务器那边有自己的有效期，
  所以停太久就得重新 `login` 一次。按需启动也能用，但"常驻"才是真正免手工的前提。
- **不做中途 `401` 重试**。过期是提前处理的（服务器不给 `expires_in` 时还会读 JWT 的 `exp`）；
  如果服务器仍然拒绝，那就是该重新登录了。
- **`chmod 0600` 只在 POSIX 有效**。Windows 上边界是你自己 profile 目录的 ACL。
- 网关**不校验** token 与签名 —— 那是 MCP 服务器的事。它只负责获取并转发。

## 排错

| 现象 | 原因 | 处理 |
|---|---|---|
| `dynamic client registration rejected` | 授权服务器关着 DCR（很多都关） | 手工注册应用并传 `--client-id` |
| `... does not advertise a registration_endpoint` | 同上，且没地方注册 | 同上 |
| 登录成功后 MCP 服务器仍报 `401 ... unexpected "aud" claim value` | token 的 audience 是 `resource`，而服务器只允许 `client_id`（或反过来） | 服务器的 audience 白名单里**两个都收** |
| 登录页能开，之后报 redirect URI mismatch | 回调地址未登记 | 登记 `http://<redirect-host>:<port>/oauth/callback`；服务器支持通配就登记 `http://localhost:*` |
| 授权服务器页面报 **"Failed to sign in"** 之类 | 打开链接的上下文在那里**没有会话** —— 内嵌预览窗口/弹窗，或另一个浏览器。有些客户端在内嵌 webview 里开链接，那种环境也完不成第三方登录 | 用你**已登录**的那个浏览器打开。`login` 本来就会自动打开默认浏览器，优先让它开。另外：**如果网关那边其实已经走完了流程，那就是成功了** —— 看 `status` 而不是你看的那个窗口 |
| 浏览器显示成功，客户端仍显示未认证 | 客户端拿到 token 了，但没绑定到这台服务器（RFC 8707 `resource`） | 同 `aud` 那一条 |
| 用得好好的，若干天后失效 | refresh token 被吊销，或服务器在这版还不支持轮转 | 重新跑 `login` |
| `Protocol "https:" not supported` | 那会是本网关的 bug | 请提 issue |

## 开发

```bash
node --test          # 32 个测试，不需要网络
```

覆盖：RFC 7636 的 PKCE 标准向量、挑战头与元数据解析、手工配置 client 的错误路径、凭据存储语义、
回环代理（**含一条"SSE 是流式转发、不是缓冲"的实测**），以及按上游协议选择传输模块。

## 特定授权服务器的笔记

- [Casdoor](docs/casdoor.md) —— DCR 行为、`aud = resource`、回调匹配规则，以及那个会悄悄把
  数据库改动覆盖回去的配置缓存。

## 许可

MIT
