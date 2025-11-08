# Mood App Worker（Cloudflare Workers + D1）

这是一个用 TypeScript 编写、部署在 Cloudflare Workers 上并使用 D1（SQLite）存储的后端示例，实现在项目根目录中的 API（参见 `src/worker.ts`）。README 以中文说明项目用途、API、数据库迁移、开发与部署步骤，并提供常用命令示例（PowerShell / Windows）。

## 主要功能

- 用户注册 / 登录（密码以 SHA-256 提交）
- 记录每日心情（按日期统计）
- 简单的匿名匹配与轮询式聊天（`anon_chat`）
- AI 聊天的轻量化 stub（规则/模板回复）
- 多个迁移文件维护 D1（SQLite）模式

## 快速概览（API 列表）

所有响应均为 JSON，格式为：

```
{ ok: boolean, data?: any, error?: string }
```

- POST /api/register — 请求体：{ username, password_sha, hobby?, sex? }
- POST /api/login — 请求体：{ username, password_sha }
- POST /api/record_mood — 请求体：{ username, mood, date? } （date 默认为当天，格式 YYYY-MM-DD）
- GET  /api/user_info?username=...
- POST /api/change_password — 请求体：{ username, old_password_sha, new_password_sha }
- POST /api/match_anonymous_chat — 请求体：{ username } → 返回 { room_id, other_username, other_hobby, other_sex, other_mood }
- GET  /api/ai_chat_data?username=... → 返回 { type_number, present_mood, interest, chief_reason, other_contents }
- POST /api/ai_chat_message — 请求体：{ username, message } → 返回 { reply }（基于简单规则）
- POST /api/end_anonymous_chat — 请求体：{ username, other_username }

匿名聊天（轮询模型）：

- POST /api/anon/send — 请求体：{ room_id, sender, recipient, message }
- GET  /api/anon/fetch?room_id=...&since=YYYY-MM-DDTHH:mm:ssZ → 返回 { messages: [...] }

默认已在 `src/worker.ts` 中对 CORS 设置为 `*`，如需限制请修改该文件。

*记得修改代码中的api端点为你的api*

## 数据库与迁移

项目使用 Cloudflare D1（兼容 SQLite 语法）。迁移文件位于 `migrations/`：

- `0001_init.sql` — 基础表（`user_table`, `chat_history`, `anon_chat` 等）
- `0002_mood_log.sql` — 为每日心情统计增加 `mood_log` 表（主键为 (username, date)）
- 后续文件（`0003_*.sql` ...）按时间顺序添加变更

示例（`mood_log`）：

```sql
CREATE TABLE IF NOT EXISTS mood_log (
	username TEXT NOT NULL,
	date TEXT NOT NULL,
	mood TEXT NOT NULL,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (username, date)
);

CREATE INDEX IF NOT EXISTS idx_mood_log_user_date ON mood_log(username, date);
```

新增或修改数据结构时，请添加新的迁移文件并通过 wrangler 应用（本地或生产）。

## 本地开发 & 运行（Windows / PowerShell）

以下命令在 PowerShell 下运行：

```pwsh
# 1) 安装依赖
npm install

# 2) 登录 Cloudflare（用于部署与 d1 操作）
npx wrangler login

# 3) （可选，首次）创建 D1 数据库
npx wrangler d1 create mood-app-db
# 记录输出中的 database_id，并在 wrangler.toml 中添加到对应 env 的 d1_databases 下：
# [[env.production.d1_databases]]
# binding = "DB"
# database_id = "YOUR_ID"

# 4) 在本地应用迁移（dev 数据库）
npx wrangler d1 migrations apply feelings --local

# 5) 启动本地开发服务器
npx wrangler dev

# 6) 将迁移应用到生产数据库
npx wrangler d1 migrations apply feelings

# 7) 部署到 Cloudflare Workers
npx wrangler deploy --env production
```

运行后，wrangler dev 会在控制台输出本地 URL，用该 URL 调用上述 API 进行调试与开发。

## 环境与配置要点

- `wrangler.toml`：绑定 D1 数据库（binding 名称建议使用 `DB`），并配置环境（比如 `env.production.d1_databases`）
- 密码传输：客户端应发送 SHA-256（hex）摘要，后端不处理明文密码
- CORS：默认允许 `*`，若上线需根据实际前端域名收紧

## Durable Objects（开发中）

该项目未来将包含一个可选的 Durable Object 实现（位于 `src/worker_durable.ts`），可用于把匿名聊天房间的消息存储在 Durable Object 实例中，从而降低对 D1 的写放大并提升小房间的读写延迟。Worker 已实现自动回退：当 Durable Object 未绑定或 DO 请求失败时，会回退到原有的 D1/`anon_chat` 表逻辑。

在 `wrangler.toml` 中添加 Durable Object 绑定示例（将 `ROOM` 绑定到 `ChatRoom` 类）：

```toml
name = "your-worker-name"
type = "javascript"

[env.production]
	# D1 binding example (existing)
	[[env.production.d1_databases]]
	binding = "DB"
	database_id = "<YOUR_DB_ID>"

	# Durable Objects binding
	[[durable_objects.namespaces]]
	binding = "ROOM"
	class_name = "ChatRoom"
	name = "ChatRoom"
```

要点：

- `binding` 需要与 `src/worker.ts` 中的 `Env` 类型（`ROOM`）一致。
- Durable Object 类名（`class_name`）须与 `src/worker_durable.ts` 中导出的类名 `ChatRoom` 匹配。

本地调试提示：

- `wrangler dev` 支持 Durable Objects（本地模拟），运行时会在控制台提示本地 URL。使用 `wrangler dev` 时请确保你的 `wrangler.toml` 已包含 `durable_objects` 配置。

如何生效：

- 项目中对匿名聊天的发送/拉取逻辑已改为优先调用 DO（路径 /do/room/:roomId/*），若 DO 未配置或发生错误则回退到原有 D1 表 `anon_chat`。因此你可以先在 `wrangler.toml` 中绑定 DO 并部署；若需要回退只需移除 DO 绑定或保持 DO 未部署，Worker 将继续使用 D1。

## 测试与验证

- 手动用 curl / Postman / 前端页面测试各端点
- 如需自动化：可编写小型集成测试脚本向本地 wrangler dev 地址发起请求

示例：记录心情（PowerShell + curl）

```pwsh
curl -X POST http://127.0.0.1:8787/api/record_mood -H "Content-Type: application/json" -d '{"username":"alice","mood":"happy"}'
```

## 注意事项与建议

- 匿名聊天目前为轮询模型（将消息保存到 `anon_chat`），若需实时通信建议使用 Durable Objects 或 WebSocket/实时方案
- AI 聊天为规则化的占位实现，若要替换请接入真实模型或外部 API，并注意并发 / 费用控制
- 若要在 CI 中跑迁移或部署，请把 `database_id` 等敏感信息放入 Secrets（Cloudflare / CI 平台）

## 后续改进（建议）

1. 添加自动化测试（极简的集成测试，覆盖用户注册、心情记录、匿名发送/拉取）
2. 在 `README.md` 中补充 API 请求/响应的示例（更多实际样例）
3. 使用 Durable Objects 实现更健壮的匿名实时匹配/房间管理
4. 在 `wrangler.toml` 中使用多环境配置并提供示例 env 文件

## 文件结构（简要）

- `src/` — 源代码（`worker.ts`, `Database.ts`, `AES.ts`, `Output.ts`, `Result.ts`...）
- `migrations/` — D1/SQLite 迁移 SQL 文件
- `wrangler.toml` — Cloudflare Workers 配置
- `package.json`, `tsconfig.json` — 项目配置
