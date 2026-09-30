# python-mcpserver — 项目计划

> **日期**: 2026-09-30
> **状态**: Phase 1–3 已实施（187 tests / ruff / mypy 全绿，仓库已推 rhosocial/python-mcpserver）
> **性质**: 私有仓库（`rhosocial/python-mcpserver`，PRIVATE）
> **发行名**: `rhosocial-mcpserver` · **import**: `rhosocial.mcpserver`
> **上游**: `rhosocial-activerecord>=1.0.0.dev30` + `mcp>=2.1`（Streamable HTTP）
> **下游**: `vistart/schedule-manager`、`vistart/contact-manager`，以及未来 N 个 MCP 业务服务

---

## 0. 立项动因

平台要建「中心化 AS + 多个 MCP 微服务」。现有两个服务暴露了同一个问题：

| 服务 | 复制了什么 | 行数 |
|---|---|---|
| `vistart/schedule-manager` | `auth.py` / `identity.py` / `errors.py` / `mcp_server.py::_ScopeEnforcement` / `models/base.py` | ~800 |
| `vistart/contact-manager` | 上述全部，逐字复制 | ~800 |

两份副本里已经出现的漂移：

- `TOOL_SCOPES` / `SCOPES` 各写一遍；
- `TokenTableVerifier` 各写一遍 —— 唯一约束是「两处必须同步」；
- `_constant_time_equals` 各写一遍。

这不是「疏忽」，而是当时的设计决定：`contact-manager/CLAUDE.md` 硬规则 11 明确写着
「不抽共享包，因为要保证服务间凭据隔离由表名维持」。**该理由在有中心 AS 之后失效** ——
隔离改由 `aud` 承担，不再由令牌表承担，复制就不再提供任何安全收益。

同时，两套本地令牌模型（`<prefix>_api_tokens` + SHA-256 查库）本身要被淘汰：
校验从「每请求一次查库」变成「本地验签、零网络往返」，这才是把它做成库的收益所在。

**因此本项目是纯替换**：业务模型（`Schedule` / `Contact`）不动，
被替换的只有「凭据 → 身份 → 授权」这条链。

---

## 1. 项目定位与边界

### 1.1 一句话

> 把「中心化 OAuth 2.1 授权服务器签发的 JWT access token」变成一个
> **rhosocial-activerecord 微服务可直接复用的 MCP Resource Server 底座**。

### 1.2 提供什么

| 能力 | 取代了下游的什么 |
|---|---|
| `JwtTokenVerifier`：JWKS 拉取/缓存/`kid` 轮换/单飞刷新 | `auth.py::TokenTableVerifier`（查库） |
| `ScopeEnforcement`：ASGI 层逐工具 403 | `mcp_server.py::_ScopeEnforcement` |
| `protected_resource_metadata()` / PRM 路由 | 各服务手写 `_send_prm` |
| `Principal` + `current_principal()` | `identity.py::current_user_id()` |
| `PrincipalScopedQuery` / `PrincipalOwnedMixin` | `models/base.py` 的一对 |
| `PrincipalMixin`（首次访问自动开户） | 两个服务都**没有** |
| `TableNamespace`（表前缀单一出处） | `contact-manager/tables.py`（只有一个服务有） |
| `mcpserver` CLI：解令牌 / 看 JWKS / 打 PRM | 无 |

### 1.3 明确不做（越界即回归）

- **不存令牌表**。本库永远不做 introspection 作为默认路径。
- **不做授权服务器**。签发 / consent / CIMD / DCR 属于未来的 `authserver` 仓。
- **不建用户表**。本地只建「投影」——`central_user_id` + 服务私有属性，没有密码、没有邮箱。
- **不认识任何业务表**。所有 DB 访问经 `Model.query()`，本库内无手写 SQL。
- **不做服务间调用授权**（token exchange / client_credentials 的校验侧留给下游）。
- **不引入 web 框架路由**。用 MCP SDK 自带的 ASGI 组合，不选 FastAPI/Starlette Router。

> 理由：本库是底座，一旦它开始「顺手帮忙」，下游就会依赖它做不该由底座做的事。
> 每一条「不做」都对应一个已经想好的诱惑，必须写下来。

---

## 2. 核心设计

### 2.1 凭据模型

```
中心 authserver
  │  签发
  ▼
JWT access token (ES256/RS256/EdDSA, TTL 5–15 min)
  │  claims: iss sub aud exp iat jti client_id scope
  ▼
本服务 ── 本地验签（JWK 缓存，命中零网络）
  │  Principal(central_user_id, client_id, scopes, issuer, jti)
  ▼
<prefix>_principals  （首次访问自动开户）
  │  principal_id (int, 本地)
  ▼
<prefix>_schedules / <prefix>_contacts  ...（外键 principal_id）
```

**「授权关系」与「数据归属」与「账户」是三台独立状态机**：

| 层 | 位置 | 吊销语义 |
|---|---|---|
| 授权（grant） | authserver，唯一吊销单元 | 吊销 → refresh 失败 → AT 最多再活一个 TTL |
| 投影（principal） | 本库 `<prefix>_principals.status` | 吊销授权**不删**这行；重新授权即恢复 |
| 账户（central user） | authserver `users.status` | 停用是第三件独立的事 |

沿用用户原始设计里唯一正确的那条：撤销授权不删数据，除非用户显式要求删除。

### 2.2 `aud` 即隔离

`aud` 绑定 RFC 8707 的 `resource` 指示符（默认等于 MCP 端点 URL），
因此 `calendar` 的令牌天然打不开 `contact-manager`，**与表名、库名无关**。
下游表前缀（`sm_` / `cm_`）从此降级为纵深防御，不再是安全边界。

### 2.3 身份出口唯一

`identity.current_principal()` 是**全库唯一**读「谁在调用」的地方。
`PrincipalScopedQuery.__init__` 与 `PrincipalOwnedMixin.prepare_save_data`
是仅有的两个强制点，与 `schedule-manager` 的既有论证一致
（接缝选在 `__init__` 而非各个终结方法，因为 `count` 与数值聚合走
`aggregate()` 而 `all()` 走 `to_sql()`，逐个覆写终结方法会静默漏掉一条路径）。

### 2.4 逐工具 scope，而非全局

`AuthSettings.required_scopes` 保持为空：SDK 的要求是全有或全无，
一个只读令牌会被连读操作一起拒掉。检查放在 ASGI 层，
因为只有那里能产出 HTTP 403；放在 `ServerMiddleware` 会变成 200 里的 JSON-RPC 错误。

---

## 3. 模块布局

```
src/rhosocial/mcpserver/
├── __init__.py        # 稳定公开 API（唯一门面，58 项）
├── config.py          # ResourceServerConfig：env 驱动的封闭词表 + 工具 scope 映射
├── errors.py          # McpServerError / Unauthenticated / ProvisioningError /
│                      #   PrincipalNotResolved / JwkUnavailable / ConfigurationError
├── identity.py        # Principal + current_principal() + request-scope memo
├── jwks.py            # JwksCache：TTL/kid 轮换/单飞/降级
├── verifier.py        # JwtTokenVerifier + 请求内 memo
├── scopes.py          # ScopeSet 封闭词表 + ScopePolicy 工具映射
├── metadata.py        # protected_resource_metadata()（RFC 9728）+ challenge 构造
├── middleware.py      # ScopeEnforcement / PrincipalResolution / ResourceEndpoints
├── tables.py          # TableNamespace（前缀单一出处）
├── orm/
│   ├── __init__.py    # assert_protected() 启动期守卫
│   ├── ddl.py         # 投影表 DDL + serial_type_for(dialect)
│   ├── principal.py   # PrincipalMixin（解析 + 首次开户 + 请求内 memo）
│   ├── scoped.py      # PrincipalScopedQuery
│   └── owned.py       # PrincipalOwnedMixin
├── app.py             # build_asgi_app() / build_mcp_app() / auth_settings() / serve()
└── cli.py             # rhosocial-mcpserver: decode / jwks / prm / policy
```

**装配顺序是承重的**（`app.py` 的模块 docstring 完整说明每层为什么必须在那个位置）：

```
ResourceEndpoints      PRM 文档、/healthz
  └── ScopeEnforcement 逐工具 403（需要读 body）
       └── PrincipalResolution 解析投影（每请求一次）
            └── SDK 应用  401 + auth ContextVar
```

> `src/rhosocial/` 保持 PEP 420 命名空间（**无** `__init__.py`），
> 与 `rhosocial.activerecord` / `rhosocial.user` 共存；
> `src/rhosocial/mcpserver/__init__.py` 是**有**的，因为本库要导出稳定门面。

---

## 4. 铁律（照抄 schedule-manager 已论证过的，不重新发明）

1. **身份永远不是工具/命令参数**。任何 `user_id` / `principal_id` 形参都不允许存在。
2. **不允许跨 principal 枚举**。`Principal` 表故意不做 scoped，
   因为管理命令需要跨用户读；因此它**永远不能**被暴露成 MCP 工具。
3. **不用 `CTEQuery` / `SetOperationQuery` / `backend.execute` 查本库任何表**。
   这三者绕过 `Model.query()`，是唯一能漏掉身份过滤的路径。
   本库内不写手写 SQL，因此这条规则无处可绕。
4. **scope 逐工具判定，不全局判定**。scope 词表只定义一次（`ResourceServerConfig.scopes`），
   同一份数据同时喂给逐工具检查与 PRM 的 `scopes_supported`，二者不得漂移。
5. **`kid` 未命中只允许刷新一次**。刷新后仍未知即 401，不循环重试。
6. **默认只接受非对称算法**。JWKS 提供公钥时接受 `HS*` 是算法混淆攻击。
7. **表名只有一个出处**（`TableNamespace`），模型和 DDL 都只读它。
   索引名由表名派生——PostgreSQL 把所有索引放在一个命名空间里，撞名会让整个建表挂掉。

---

## 5. 实施阶段

### Phase 1 — 凭据链（无数据库依赖，可独立单测）✅

- [x] `config.py` / `errors.py` / `scopes.py` / `tables.py`
- [x] `jwks.py`：TTL + `Cache-Control` 夹取 + `kid` 轮换 + `asyncio.Lock` 单飞 +
      网络失败时若有可用缓存则降级 + 并发只打一次网络
- [x] `verifier.py`：算法白名单、`iss`/`aud`/`exp` 校验、
      请求内 memo（避免 SDK 与中间件各验一次签名）
- [x] `identity.py`：`Principal` 冻结数据类 + 唯一出口 + CLI 通道
- [x] `metadata.py`：RFC 9728 文档
- [x] `middleware.py`：PRM / health / body 限额 / 逐工具 403
- [x] 全量单测（JWKS 轮换、算法混淆、aud 不匹配、无签名密钥、403 挑战头…）

### Phase 2 — ORM 归属链 ✅

- [x] `orm/principal.py`：`PrincipalMixin.resolve()` + 首次访问自动开户
- [x] `orm/scoped.py` / `orm/owned.py`
- [x] 投影表 DDL 构造器（`IF NOT EXISTS`，无迁移）
- [x] SQLite 实库测试

### Phase 3 — 装配与 CLI ✅

- [x] `app.py`：`build_asgi_app()` / `build_mcp_app()` / `auth_settings()` / `serve()`
- [x] `cli.py`：`decode` / `jwks` / `prm` / `policy`
- [x] 端到端测试：真实 `MCPServer` + MCP SDK 官方客户端，走真实 HTTP

### Phase 3.5 — 下游接入（未开始）

- [ ] `schedule-manager` 切换（保留 `AUTH_ISSUER` 未配置时回落本地表）
- [ ] `contact-manager` 切换

### Phase 4 — 互操作验证

- [ ] OpenCode / Cursor / Claude Code / Codex 四个客户端首次连接全流程
- [ ] 令牌轮换与吊销的端到端时序

### 不在本项目范围

authserver（签发端）、企业 EMA、组织策略、服务间 token exchange。

---

## 6. 待定案（下游接入前必须拍板）

| # | 问题 | 倾向 | 后果 |
|---|---|---|---|
| 1 | CLI / 本地调用用 client_credentials 还是保留本地静态令牌？ | client_credentials | 下游要在 authserver 注册自己为 client |
| 2 | `aud` 默认等于 MCP 端点 URL，还是一个逻辑 API id？ | 端点 URL（RFC 8707 原生） | 若 authserver 用逻辑 id，需在配置里显式列出 `audience` |
| 3 | 迁移是否双校验器并行？ | 是 | `AUTH_ISSUER` 未配置时回落 `<prefix>_api_tokens` 查表 |
| 4 | 投影表主键用 `central_user_id`（字符串）还是本地 int？ | 本地 int `principal_id` + 唯一索引 | 业务表存 int，等值谓词走索引；`central_user_id` 变更不影响外键 |

---

## 7. 验证方式

```bash
cd /mnt/i/GitHubRepositories/rhosocial/python-mcpserver
source .venv3.14-ubuntu26.04/bin/activate
export PYTHONPATH=src:tests
pytest tests/ -q          # 全量
ruff check src/ tests/    # lint
mypy src/                 # 类型
```

> 与核心库一致：行宽 100（`[tool.ruff]`），测试走 SQLite 真库而非 mock。

---

## 8. 实施中修正的三个真问题

记在这里，因为它们都不是「写错了」，而是**沉默地错了，只有实测才暴露**：

1. **`SERIAL` 在 SQLite 上不是 rowid 别名。** SQLite 接受任意类型名，于是
   `"id" SERIAL PRIMARY KEY` 建出一个名叫 SERIAL 的普通列，`INSERT` 写入字面
   `NULL`，每行读回来 id 都是空的——最终以 `int() argument must be … not
   'NoneType'` 的形式出现在开户路径上，与类型毫无关系。已加
   `serial_type_for(dialect)`：按方言自己的类型亲和规则问一次。
2. **`PrincipalResolution` 里的 `from ..identity` 多写了一层。**
   `middleware.py` 直接位于 `rhosocial/mcpserver/` 下，`..` 会到 `rhosocial`。
   这是 mypy 抓出来的**真 import 错误**，不是类型洁癖。
3. **`_create` 用 `hasattr(cls, "provided_by")` 判断字段是否存在。**
   pydantic v2 的模型类不把字段暴露为类属性，于是守卫会**静默跳过**赋值，
   `provided_by` 永远是空的。已改用 `model_fields`。

第四个是设计层面的：`auth` 与 `token_verifier` 必须传给 `MCPServer(...)`
**构造器**，SDK 不接受它们出现在 `streamable_http_app()` 上。而一个漏传
`auth` 的 `MCPServer` 会**把工具开放给所有人且不发一言**——所以
`build_mcp_app()` 检查而非假设，漏传直接抛 `ConfigurationError`。

## 8.5 阻塞项：核心库 `1.0.0.dev30` 未发布（2026-09-30）

CI 两次推送都是红的，**不是私有仓计费**——GitHub Actions 正常执行了 19 秒，
两个 job 都死在依赖解析。要点记录在此，因为它改变了下游的排期。

### 事实

| | |
|---|---|
| 本仓 `pyproject.toml` pin | `rhosocial-activerecord>=1.0.0.dev30` |
| PyPI 最新 | `1.0.0.dev29` |
| `python-activerecord` 公网 `main` | `1.0.0.dev29` |
| `dev30` 在哪 | 仅存在于本机 `feature/readonly-object-type-query-named-examples`（commit `436a233d`），**该分支未 push** |
| `dev29` 是否够用 | 不够。`interface/update.py` 里只有 `IUpdateBehavior`，没有 `IDataPreparationBehavior`——`PrincipalOwnedMixin` 继承的正是后者 |

所以 pin 是**对的**，问题在于被 pin 的版本从未离开过这台机器，
而 CI runner 拿不到任何含它的东西。

### 已修（本次提交）

1. **删掉 workflow 里的 `pip install -e ../python-activerecord`。** 它在
   runner 上永远失败（那个路径不存在），而且 `||` 只兜 exit code，
   仍会先打印一句误导性的 `not a valid editable requirement`。
2. **新增 `scripts/check_core_version.py`**，在安装前检查 pin 是否可获取，
   失败时直接说明「索引上最新是 dev29」而不是抛一堵 `ResolutionImpossible`。
   单独一个 `preflight` job，因为这是最难诊断的那类失败。
3. **`CORE_SOURCE` 收敛成 workflow 顶部一个变量**，附注了何时切回版本 pin。
4. **删掉 `published-core` job。** 在 dev30 发布前它恒红，
   恒红的 job 会训练所有人忽略红色。
5. 版本上报改用 `importlib.metadata`——核心库是 PEP 420 命名空间包，
   没有 `__version__` 属性。

### 决定：走 B（2026-09-30）

核心库的 `feature/readonly-object-type-query-named-examples` 已 push，
CI 的 `CORE_SOURCE` 指向它。`pyproject.toml` **仍保留版本 specifier**，
不写成 git URL——PyPI 上传时会拒绝直接 URL 依赖，且从索引装本包的消费者
也无法 clone 核心库。

### 为什么 `dev29` 真的不行（实测，不是推断）

试过让代码兼容 `dev29`，用干净 venv 跑完整套件，两处硬伤：

| 需要的东西 | dev29 | dev30 |
|---|---|---|
| `IDataPreparationBehavior`（`PrincipalOwnedMixin` 继承的保存钩子） | 无（只有 `IUpdateBehavior`） | 有 |
| `ColumnConstraint` | 纯 dataclass，**不带 dialect** | `BaseExpression`，构造首参是 dialect |
| 保存钩子的派发方式 | `base.py:1056` 用 `hasattr` 鸭子派发 | 显式接口 |

第一项其实**可以**绕过——`hasattr` 派发意味着只要定义方法即可，无需继承。
但第二项不行：`orm/ddl.py` 的 `column()` 助手按 dev30 的签名构造
`ColumnConstraint`，在 dev29 上直接 `TypeError: got multiple values for
argument 'name'`。所以 `>=1.0.0.dev30` 是对的 pin。

顺带记一个反直觉的点：绕过继承会**主动隐藏**版本差异。
若某天核心库把派发改成「只认显式接口继承」，软导入就会静默失效——
`prepare_save_data` 不再被调用，归属强制消失且无人报错。
宁可保持硬导入、让缺 API 在 import 时就说清楚。

### B 的代价（已记录在 workflow 注释里）

`CORE_SOURCE` 指向的是**分支**而非 tag：它会移动，同一 commit 的两次 CI
可能装到不同的核心代码；一次绿灯不说明发布后能装到什么。
dev30 发布后，改回版本 pin + 删掉 `preflight` 即可，其余不动。

### 干净 venv 复现发现的第二个缺口

模拟 CI 的全新 venv 时又暴露一个本地永远看不到的问题：
**`aiosqlite` 没在 `dev` extras 里**。核心库的异步 SQLite 后端在模块级
import 它，而本包没有任何地方提到它——我的本地 venv 是早先手工装上的，
所以测试从没检验过依赖声明。已补。

这与最初那次失败同源：**只存在于我机器上的依赖**。

## 9. 风险与已知代价

| 风险 | 处置 |
|---|---|
| JWKS 首请求有网络延迟 | 预热：`JwksCache.prefetch()` 在 lifespan 里先拉一次 |
| AS 私钥轮换与 `kid` 未命中的竞态 | 一次刷新 + 5 秒负缓存，防抖 |
| 撤销传播窗口 = AT TTL（5–15 min） | 高危操作由下游自行加 introspection 侧信道；本库不代劳 |
| 下游两服务同时改导致各自半新半旧 | `AUTH_ISSUER` 双校验器并行 2 个版本后再删本地表 |
| `register_projection` 是进程级全局 | 设计如此：一个进程服务一个服务，所以只有一个答案。测试里显式清空，并在 `PrincipalResolution` 上留 `resolve_projection=False` 供不使用 ORM 归属层的服务显式关掉 |
| SDK 升级改动 `streamable_http_app` 签名 | 端到端测试用官方客户端跑通全流程，会先于下游服务发现 |
| 本地绿 ≠ CI 绿 | 本地全部测试跑的是**特性分支的 editable 安装**，不是任何可发布产物。`preflight` 是为此加的：让「pin 不可获取」在 5 秒内以一行字失败。**并且**任何依赖声明的改动，都要在一个全新 venv 里按 CI 的步骤复现一遍才算验证过——`aiosqlite` 就是这么漏的 |
| 本库成为「什么都往里塞」的垃圾桶 | §1.3 的六条「不做」是验收项，不是建议 |
