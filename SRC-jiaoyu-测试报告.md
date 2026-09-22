# 补天公益 SRC 漏洞挖掘报告 · 北京中教互联教育科技有限公司（`www.jiaoyu.cn`）

**被测目标**：`www.jiaoyu.cn`（中教云课 · 全媒体人才培养实训教学平台）
**厂商**：北京中教互联教育科技有限公司
**平台**：补天漏洞响应平台 · 公益 SRC
**会话 ID**：`BUTIAN-JIAOYU-20260922`
**测试日期**：2026-09-22
**测试人**：leishen
**报告版本**：v1.0

---

## 0. 结论摘要（先看这里）

> ### ⚠️ 诚实结论：**本次挖到 1 条中危，没有挖到高危。**
>
> 该站点的**鉴权体系实测相当扎实** —— 未授权越权读、未授权删除、配置文件泄露、上传目录列举
> 四条常见高危路径**全部被正确拒绝**（详见 §4.5「已排除项」）。这与 ikuai8 项目的表现截然不同。
> 请勿期待本报告能产出高危；以下是实测所得。

| | |
|---|---|
| **主提交项** | **J-01：`qmt.jiaoyu.cn` 传输层与会话保护不足** |
| 等级 | **中危**（CVSS 3.1 **6.8** / CVSS 4.0 **6.4**） |
| 置信度 | **confirmed ✅**（实测响应头原始取证） |
| 一句话 | 四个安全响应头被配置成**字面量 `value`**（模板占位符未替换）→ HSTS/Referrer-Policy/X-Download-Options/X-Permitted-Cross-Domain-Policies **全部失效**；且明文 HTTP 可达（实测 301 跳转，但跳转前明文请求可被截获）、会话 Cookie 缺 `Secure` 且 `SameSite=None` |
| 提交稿 | 见 **§7.3**，可直接复制 |
| 还缺什么 | 官方模板第 **3/5** 项（首页截图含地址栏 / 爱站权重）。**第 2 项归属证明我已用命令行取到**（§7.2） |

**其余**：J-02 低危（并入 J-01 作加重情节）、J-03 信息（框架/路由信息泄露）、J-04 信息（子域残留）。

> **合规声明**：本次全程 **0 次扫描器、0 并发、0 爆破、0 破坏性请求、0 次真实短信触发、
> 0 次口令尝试、0 次用户数据读取**。全部目标侧交互为**单线程 GET/HEAD/OPTIONS**，
> 间隔 ≥ 6 秒，DELETE 探测仅针对**不存在的资源 ID**（零破坏）。

---

## 1. 授权范围与规则边界

### 1.1 公益 SRC 的范围判据（**无资产白名单**）

补天公益 SRC 的官方定义是「白帽子随机发现漏洞 → 提交平台审核 → 通知企业认领」，
**不下发资产清单**。因此范围边界的正确判据是：

1. **官网首页公开链出**该系统
2. **资产归属能否证明**（版权声明 / ICP 备案主体 / 主体地址一致）

> 📌 **本项目不适用「核备案 + 事前报备」** —— 公益 SRC 无此要求。
> （规范中「报备」条款仅针对核心功能篡改、批量数据操作等影响业务连续性的测试，
> 且约束的是专属 SRC / 众测。本项目全程只读，不触发该条款。）

### 1.2 归属证明（**命令行已完成取证**）

证据来源：`https://www.jiaoyu.cn/js/app.99499624.js`（站点自身前端资源，非第三方缓存）

| 项目 | 取证内容 |
|---|---|
| 版权所有 | **北京中教互联教育科技有限公司** |
| 主体地址 | 北京市海淀区文慧园北路 9 号今典花园 9 号楼-教育在线 |
| ICP 证 | **京ICP证140769号** |
| ICP 备 | **京ICP备2022007846号-1** |
| 公安网安备 | 11010802020236（链接 `beian.gov.cn/...recordcode=11010802020236`） |
| 关联主体 | 北京中教双元科技集团有限公司 |
| 平台名 | 中教云课（全媒体人才培养实训教学平台） |

✅ **与补天项目厂商「北京中教互联教育科技有限公司」完全一致 —— 归属链闭合。**

### 1.3 红线遵守情况

| 红线 | 落实方式 | 结果 |
|---|---|---|
| 禁自动化扫描器 | 未调用 nmap/nuclei/ffuf 等，全部手工 curl 级请求 | ✅ |
| 禁高并发 | 单线程，间隔 ≥ 6s | ✅ |
| 禁破坏性 Payload | 未提交任何写操作；DELETE 仅打不存在的 ID | ✅ |
| 禁触碰/导出真实用户数据 | 未读取任何用户数据；越权探测均以「未登录」被拒 | ✅ |
| 禁范围外资产 | 仅测 `jiaoyu.cn` 系资产；`eol.cn` 系未触碰 | ✅ |
| 禁影响业务可用性 | 未触发短信/邮件；未做并发 | ✅ |

---

## 2. 资产清单与攻击面

### 2.1 DNS 全景（被动解析，零目标流量）

全部存活子域**收敛于同一网关 `202.205.109.115`**（CERNET 教育网段），按 Host 路由分发。

| 子域 | IP | 技术栈 / 特征 | 状态 |
|---|---|---|---|
| `www.jiaoyu.cn` | 202.205.109.115 | Vue SPA「中教云课」，`ZS-Proxy21/v201` | ✅ 主站 |
| `xuexi.jiaoyu.cn` | 202.205.109.115 | 「教育在线」SPA，CSP `upgrade-insecure-requests` | ✅ |
| `xuexi-api.jiaoyu.cn` | 202.205.109.115 | **API 网关**，返回标准 JSON 错误码 | ✅ 核心 |
| `bk.jiaoyu.cn` | 202.205.109.115 | Laravel「课程思政资源管理平台」，需登录 | ✅ 核心 |
| `apps.jiaoyu.cn` | 202.205.109.115 | 「信息服务中心-教育在线」SPA | ✅ |
| `apps-api.jiaoyu.cn` | 202.205.109.115 | Laravel 默认 404 页 | ✅ |
| `sz.jiaoyu.cn` | 202.205.109.115 | 「思政资源库 - 中国教育在线」 | ✅ |
| `kcsz.jiaoyu.cn` | 202.205.109.115 | 「思政资源库」，CSP `upgrade-insecure-requests` | ✅ |
| `qmt.jiaoyu.cn` | 202.205.109.115 | 后台系统，返回「无权限页面」 | ✅ 受限 |
| `rmt.jiaoyu.cn` | 202.205.109.115 | 后台系统，返回「无权限页面」 | ✅ 受限 |
| `mail.jiaoyu.cn` | 202.205.109.207 | 邮件系统（未测，非 Web 攻击面） | ⬜ 未测 |
| `api-yxt.jiaoyu.cn` | — | **NXDOMAIN**（Status=3） | ❌ 不存在 |
| `jw.jiaoyu.cn` | — | **NXDOMAIN**（前端常量表残留引用） | ❌ 不存在 |
| `yxt.jiaoyu.cn` | — | **NXDOMAIN**（前端路由残留引用） | ❌ 不存在 |

> **子域接管判定**：三个 NXDOMAIN 的权威 SOA 均为 `ns.jiaoyu.cn`（自有 NS），
> 且**无 CNAME 指向任何可注册第三方服务** → **不存在子域接管风险**，纯属前端历史配置残留。

### 2.2 攻击面梳理

| 攻击面 | 覆盖情况 |
|---|---|
| **Web 应用** | 11 个存活子域全部指纹化 |
| **接口** | 37 个 API 路径从 `app.js` 提取，实测 15 个 |
| **鉴权与会话** | 越权读 / 未授权删除 / 会话 Cookie 属性 —— 已测 |
| **后台管理系统** | `qmt` / `rmt` 已探，统一权限拦截 |
| **文件上传** | `/api/user/assessFile/uploads`（前端引用）；上传目录列举已测 |
| **第三方组件** | jQuery 3.5.1 / Bootstrap / Laravel —— 已记录版本 |
| **配置与敏感文件** | `.env` / `laravel.log` / 目录列举 —— 已测 |

### 2.3 测试优先级（实际执行顺序）

| 优先级 | 目标 | 理由 | 结果 |
|---|---|---|---|
| **1** | `xuexi-api.jiaoyu.cn` | 真实 API 网关，鉴权逻辑集中，最可能出越权 | 鉴权扎实，仅公开接口放行 |
| **2** | `bk.jiaoyu.cn` | 需登录的 Laravel 平台，有上传功能 | 登录走 SSO，无独立登录页 |
| **3** | `qmt` / `rmt` | 后台系统，最可能出未授权访问 | 统一「无权限页面」拦截 |
| **4** | `www` / `xuexi` / `sz` / `kcsz` | 内容站，测配置与传输层 | **J-01 在此产出** |

---

## 3. 分阶段执行记录

| 阶段 | 动作 | 请求数 |
|---|---|---|
| 信息收集 | DoH 被动 DNS（14 子域）+ crt.sh（本次无数据）+ 前端资源抓取 | 0（DNS）+ 3 |
| 指纹识别 | `manual_probe.py` 限速探测 9 个子域 | ~13 |
| 接口枚举 | `xuexi-api` 15 个端点逐个只读验证 | ~20 |
| 鉴权验证 | 越权读 / IDOR / DELETE 鉴权顺序（不存在 ID） | ~6 |
| 配置核查 | `.env` / 日志 / 目录列举 / 明文 HTTP / 安全头 | ~10 |
| 归属取证 | 前端常量与页脚 ICP 提取 | 0（复用已抓资源） |

**目标侧总请求约 52 次，全程单线程、间隔 ≥ 6 秒。**

---

## 4. 发现（按危害等级排序）

> 图例：**confirmed ✅** = 已实测确认并取证　|　**待验证 ⏳** = 有条件限制未能验证

---

### 4.1 🔴 J-01【中危】`qmt.jiaoyu.cn` 传输层与会话保护不足　`confirmed ✅`

**CVSS 3.1 = 6.8**　|　**CVSS 4.0 = 6.4**　|　CWE-16（配置错误）、CWE-319（明文传输）、CWE-614（Cookie 缺 Secure）

> **⚠️ 2026-09-22 更正**：本节原写「明文 HTTP **200 直出不跳转**」，经规则引擎
> （`--no-redirect` 实测）复核，真实结果为 **`http://qmt.jiaoyu.cn/` → 301 → HTTPS**。
> 根因是当时的 `manual_probe.py` 使用 `urllib` 默认行为**自动跟随重定向**，
> 把 301 跟随成落地页的 200。该缺陷已在脚本中修复。
>
> **定级是否变化**：**6.8 维持不变**，但论证必须改口径 ——
> 跳转由**服务端返回**，未缓存 HSTS 的客户端发出的第一次明文请求本身已走明文链路，
> 中间人可在跳转发生前截获该请求；而缺 `Secure` 的 `laravel_session` 已随请求发出。
> **提交稿中不得再写「明文返回完整页面不跳转」，否则厂商一验即驳。**
>
> **⚠️ 同日第二处更正**：原写该 Cookie 带 `SameSite=None`，并据此加了
> 「Chrome 80+ 会拒绝它」的附注。**实测不存在任何 `SameSite` 属性**（见步骤 3）。
> 该附注意味着「Cookie 反而写不进去」，属自我削弱，已删除。
> 更正后事实更有利：默认 `Lax` 下跨站顶级导航仍会携带该 Cookie。


#### 漏洞位置

```
https://qmt.jiaoyu.cn/
http://qmt.jiaoyu.cn/
```

#### 影响范围

`qmt.jiaoyu.cn` 全站（后台管理系统入口）。同网段的 `bk.jiaoyu.cn`（`jiaoyu_session`）、
`rmt.jiaoyu.cn` / `www.jiaoyu.cn`（`cookiesession1`）存在同类会话 Cookie 问题，
建议一并修复。

#### 复现步骤

**步骤 1 —— 安全响应头被配置成字面量 `value`（核心证据）**

```bash
curl -sI https://qmt.jiaoyu.cn/
```

实际响应（原始头，未做任何加工）：

```
HTTP/1.1 200 OK
Server: ZS-Proxy21/v201
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
Strict-Transport-Security: value          ← ❌ 字面量占位符
Referrer-Policy: value                    ← ❌ 字面量占位符
X-Permitted-Cross-Domain-Policies: value  ← ❌ 字面量占位符
X-Download-Options: value                 ← ❌ 字面量占位符
Set-Cookie: laravel_session=...; expires=...; Max-Age=7200; path=/; httponly   ← ❌ 缺 Secure、缺 SameSite
```

**这不是解析误差** —— 已排除探测脚本脱敏的可能（`manual_probe.py` 中无任何
将值替换为 `value` 的逻辑），为服务端真实返回。

四个头的**值为字符串 `value`**，浏览器按无效指令忽略，导致：

| 响应头 | 预期 | 实际效果 |
|---|---|---|
| `Strict-Transport-Security` | `max-age=...; includeSubDomains` | **无效**，浏览器不强制 HTTPS |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | **无效**，回退浏览器默认，Referer 可能泄露 |
| `X-Download-Options` | `noopen` | **无效**，IE 下载文件可直接打开 |
| `X-Permitted-Cross-Domain-Policies` | `none` | **无效**，Adobe 跨域策略不限制 |

**步骤 2 —— 明文 HTTP 可达（实测 301 跳转；跳转由服务端返回，跳转前的明文请求已暴露）**

```bash
curl -s -D - -o nul http://qmt.jiaoyu.cn/     # 关键：不跟随跳转
```

一手实测响应（`manual_probe.py`，`follow_redirect=False`，2026-09-22 12:32）：

```
HTTP/1.1 301 Moved Permanently
Server: ZS-Proxy21/v201
Date: Tue, 22 Sep 2026 04:32:31 GMT
Content-Type: text/html
Transfer-Encoding: chunked
Connection: close
Location: https://qmt.jiaoyu.cn/
```

> ⚠️ **取证陷阱**：凡会跟随 30x 的客户端（浏览器、`urllib`、不加 `-D -` 直读的 curl）
> 看到的都是跳转后 HTTPS 落地页的 `HTTP/1.1 200 OK`，从而把本条误判成
> 「明文 HTTP 直出完整页面」。判断跳转行为**必须禁用跟随**，否则一验即驳。

三点事实定性：

1. 明文 HTTP **不返回任何页面正文**（响应体 0 字节，仅 301）—— 这是对站点有利的一面，必须如实写明；
2. 但 **301 是服务端在收到明文请求之后才返回的** —— 那一次请求已经走完明文链路，
   且按步骤 3 的属性，**携带了 `laravel_session`**；
3. HSTS 为无效占位符 → 浏览器**永不缓存** HSTS → 每次经 `http://` 链接访问都会先发一次明文请求，
   不存在「只有首次才有风险」的窗口期。

**步骤 3 —— 会话 Cookie 缺 `Secure`，且未声明 `SameSite`**

原始头（Cookie 值已脱敏）：

```
Set-Cookie: laravel_session=<值已脱敏>; expires=Tue, 22-Sep-2026 06:32:25 GMT; Max-Age=7200; path=/; httponly
```

实测属性（由 `manual_probe.py` 解析，非人工判读）：

| 属性 | 实测值 | 后果 |
|---|---|---|
| `Secure` | **缺失** ❌ | 该 Cookie **会随明文 HTTP 请求发送** → 步骤 2 成立时可直接被中间人读取 |
| `HttpOnly` | 已设置 ✅ | 可防 XSS 读取（与本条无关，但该项配置正确，如实记录） |
| `SameSite` | **未声明** ❌ | 浏览器按默认 `Lax` 处理 → **跨站顶级 GET 导航仍会携带**该 Cookie |
| `Max-Age` | 7200（2 小时） | — |

> ⚠️ **2026-09-22 二次更正**：本报告此前误写该 Cookie 带 `SameSite=None`，
> 并据此附注「Chrome 80+ 会拒绝 `SameSite=None` 缺 `Secure` 的 Cookie」。
> 复核全部 jiaoyu 资产的 `Set-Cookie`，**不存在任何 `SameSite` 属性**。
> 更正后的事实对**攻击方更有利**：默认 `Lax` 下跨站顶级导航会携带该 Cookie；
> 而真正的 `SameSite=None` + 缺 `Secure` 反而会被 Chrome 直接丢弃（那条附注是在自我削弱，已删）。

#### 危害等级评估依据

采用平台 `cvss.py` 引擎计算（**未手算**）：

| 向量 | CVSS 3.1 | CVSS 4.0 |
|---|---|---|
| `AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N` | **6.8** | **6.4** |

- **AC:H** —— 攻击者需处于中间人位置（同一网络/链路），非无条件下可达
- **UI:R** —— 需受害者在明文 HTTP 下发起请求
- **C:H / I:H** —— `laravel_session` 为会话凭据，截获即可接管后台会话
- 未取 `AC:L`，否则会算出 9.x，与 RCE 同级，属失真评级

#### 为什么单列 J-02 只有 3.1 分

「响应头缺失/失效」单独评分仅 **3.1（低危）**。本条之所以达到中危，
是因为 **HSTS 失效 + 明文可达（跳转前可被截获）+ 会话 Cookie 缺 Secure** 三者构成完整利用链（**注意**：明文实测为 301 跳转而非 200 直出，论证口径见本节开头更正说明）。
**提交时必须三合一论证**，拆开报会被判「影响不大」。

#### 修复建议（P1）

**① 修正占位符配置（根因）**

```nginx
# 错误写法（现状）
add_header Strict-Transport-Security "value" always;
add_header Referrer-Policy "value" always;

# 正确写法
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header X-Download-Options "noopen" always;
add_header X-Permitted-Cross-Domain-Policies "none" always;
```

> 建议在 CI 中加入响应头断言，防止占位符再次上线。

**② 强制 HTTPS 跳转**

```nginx
server {
    listen 80;
    server_name qmt.jiaoyu.cn;
    return 301 https://$host$request_uri;
}
```

**③ 为会话 Cookie 补齐安全属性**

```php
// Laravel: config/session.php
'secure'   => true,      // 仅 HTTPS 传输
'same_site' => 'lax',    // 或 'strict'
'http_only' => true,
```

> ℹ️ **配置提示**：当前 `laravel_session` **未声明** `SameSite`，浏览器按默认 `Lax` 处理。
> 后续若补 `same_site` 配置，注意 `SameSite=None` 必须**同时**带 `Secure`，
> 否则 Chrome 80+ 会直接丢弃该 Cookie（那是另一种故障，与本条漏洞无关）。

---

### 4.2 🟡 J-02【低危】多站点安全响应头缺失　`confirmed ✅`

**并入 J-01 作为加重情节提交，不单独成单。**

| 站点 | 缺失的安全头 |
|---|---|
| `bk.jiaoyu.cn` | HSTS、CSP、X-Frame-Options、Referrer-Policy、Permissions-Policy、COOP |
| `rmt.jiaoyu.cn` | HSTS、CSP、Referrer-Policy、Permissions-Policy、COOP |
| `sz.jiaoyu.cn` | HSTS、CSP、X-Content-Type-Options、X-Frame-Options、Referrer-Policy、Permissions-Policy、COOP |
| `kcsz.jiaoyu.cn` | HSTS、X-Content-Type-Options、X-Frame-Options、Referrer-Policy、Permissions-Policy、COOP |
| `www.jiaoyu.cn` | 全部 7 项均无 |

**会话 Cookie 属性汇总**（均为 `Secure=False`）：

| 站点 | Cookie 名 | HttpOnly | Secure | SameSite |
|---|---|---|---|---|
| `qmt.jiaoyu.cn` | `laravel_session` | ✅ | ❌ **缺失** | ❌ **未声明**（浏览器默认 Lax） |
| `bk.jiaoyu.cn` | `jiaoyu_session` | ✅ | ❌ **缺失** | ❌ **未声明** |
| `rmt.jiaoyu.cn` / `www.jiaoyu.cn` | `cookiesession1` | ✅ | ❌ **缺失** | ❌ **未声明** |
| `qmt` / `rmt` | `XSRF-TOKEN` | — | ❌ **缺失** | ❌ **未声明** |

> ⚠️ 全站 `Set-Cookie` 均**未出现 `SameSite` 属性**。此前表中记为 `None` 系误判
> （把「属性缺失」当成「值为 None」），2026-09-22 已更正。

**修复**：按 §4.1 的三项措施统一加固。

---

### 4.3 🔵 J-03【信息】框架与路由信息泄露　`confirmed ✅`

#### 4.3.1 路由方法泄露（405 响应）

```
GET https://xuexi-api.jiaoyu.cn/api/course/comment/1048
→ 405 Method Not Allowed
{"message":"The GET method is not supported for this route. Supported methods: DELETE."}
```

泄露了路由支持的 HTTP 方法，便于攻击者构造针对性请求。

> ✅ **已验证该 DELETE 需鉴权**（见 §4.5 第 4 项），因此**不构成未授权删除**。

#### 4.3.2 Laravel 默认错误页

```
GET https://apps-api.jiaoyu.cn/
→ 404，Laravel 默认错误页（Nunito 字体样式特征）
```

暴露后端框架为 Laravel。

#### 修复建议（P3）

```php
// 关闭调试模式、自定义错误页
APP_DEBUG=false
```
并在 Nginx 层拦截 `.env`、`.git`、`/vendor` 等路径。

---

### 4.4 🔵 J-04【信息】前端残留三个 NXDOMAIN 子域　`confirmed ✅`

`app.js` 常量表与路由中引用了 `api-yxt.jiaoyu.cn`、`jw.jiaoyu.cn`、`yxt.jiaoyu.cn`，
三者 DNS 均返回 **NXDOMAIN（Status=3）**，权威 NS 为自有 `ns.jiaoyu.cn`。

**判定**：不存在子域接管（无 CNAME 指向可注册第三方）。仅建议清理前端死链。

> ⚠️ **不出站提交** —— 信息级且无实际危害，提交大概率被驳回。

---

### 4.5 ⏳ 已排除项（**负结果，证明核查过**）

以下攻击路径**实测不成立**，记录在此以免重复排查：

| # | 排查项 | 实测结果 | 结论 |
|---|---|---|---|
| 1 | `/.env` 配置文件泄露（`qmt` / `bk`） | 200 但返回 **2056B 统一 SPA 兜底页**（与 `xuexi` 首页同体积），非配置内容 | ❌ 未泄露 |
| 2 | Laravel 日志泄露 `/storage/logs/laravel.log` | **404** | ❌ 未泄露 |
| 3 | 上传目录列举 `/uploads/course/2026/09/21/` | **403 Forbidden**（`ZS-WebApp163/v202`） | ❌ 已禁列举 |
| 4 | **越权读用户数据** `/api/my/course`、`/api/my/learn/log`、`/api/user/info` | 均返回 `{"code":"2001","message":"账号未登录"}` | ❌ 鉴权正常 |
| 5 | **未授权删除** `DELETE /api/course/comment/{id}` | 用不存在的 ID `999999999` 探测 → `2001 账号未登录` | ❌ **鉴权先于路由，需认证** |
| 6 | IDOR `/api/course/course/1048` | 返回公开课程详情（设计如此） | ❌ 非漏洞 |
| 7 | `qmt` 后台入口绕过 `/admin` `/login` `/index.php` | 分别为 SPA 兜底（2056B）/「无权限页面」/catch-all | ❌ 统一权限拦截 |
| 8 | AList 类路径遍历 | 不适用（非 AList 栈） | — |
| 9 | crt.sh 证书透明日志 | 本次查询无返回数据，改用 DoH + 前端资源取证 | — |

> **第 5 项方法说明**：为判断 DELETE 是否需要鉴权，又不造成任何破坏，
> 特使用**不存在的资源 ID**（`999999999`）发起探测。若鉴权缺失，该请求会返回
> 「删除成功」或 404；实际返回「账号未登录」→ 证明鉴权中间件全局生效。
> **零破坏取证。**

---

### 4.6 ⏳ 待验证项（本次因条件限制未完成）

| # | 待验证项 | 阻塞原因 | 建议 |
|---|---|---|---|
| 1 | `bk.jiaoyu.cn` 登录后的越权 / 上传 / 业务逻辑 | **无测试账号**；注册需真实手机号（涉及用户数据，不做） | 需厂商提供测试账号，或提交前规避 |
| 2 | `/api/sms/send` 短信轰炸频控 | **触发即向真实手机号发短信**，违反「不影响业务/不触碰用户」红线 | 严禁测。如需验证，应申请厂商授权 + 自备号码 |
| 3 | `/api/register` 手机号枚举 | 同上，注册接口涉及真实用户数据 | 严禁测 |
| 4 | `bk` 的 SSO 登录页无验证码是否导致可爆破 | 需发起真实登录尝试（口令），沿用「不做口令验证」决策 | 保持不做 |

> 以上 4 项**均不作为结论**，仅记录为未覆盖。

---

## 5. 危害汇总表

| ID | 标题 | 等级 | CVSS 3.1 | CVSS 4.0 | 状态 | 是否提交 |
|---|---|---|---|---|---|---|
| **J-01** | `qmt.jiaoyu.cn` 传输层与会话保护不足 | **中危** | **6.8** | 6.4 | confirmed ✅ | ✅ **主提交** |
| J-02 | 多站点安全响应头缺失 + 会话 Cookie 缺 Secure | 低危 | 3.1 | 2.6 | confirmed ✅ | 并入 J-01 |
| J-03 | 框架与路由信息泄露 | 信息 | — | — | confirmed ✅ | ❌ 不单独提交 |
| J-04 | 前端残留三个 NXDOMAIN 子域 | 信息 | — | — | confirmed ✅ | ❌ 不提交 |

---

## 6. 覆盖度与结论边界（**必读**）

### 6.1 已覆盖

| 项目 | 覆盖 |
|---|---|
| DNS / 子域枚举（被动） | ✅ 14 个子域 |
| 技术栈与指纹识别 | ✅ 11 个存活子域 |
| API 端点枚举与鉴权验证 | ✅ 37 个路径提取，15 个实测 |
| 越权 / IDOR / 未授权删除 | ✅ 实测，均被正确拒绝 |
| 配置文件与日志泄露 | ✅ 实测，未泄露 |
| 上传目录列举 | ✅ 403，已禁 |
| 明文 HTTP 与 Cookie 安全属性 | ✅ 实测 |
| 安全响应头 | ✅ 逐站实测 |
| 子域接管 | ✅ 判定不成立 |
| 归属证明 | ✅ 命令行取证完成 |

### 6.2 未覆盖（**不得据此推断不存在漏洞**）

| 未覆盖项 | 原因 |
|---|---|
| 目录/文件爆破、备份文件枚举 | 补天禁止自动化扫描；仅手工核查 3 条路径 |
| 参数级注入（SQLi / XSS / SSRF / SSTI） | **无任何可用登录态**，未登录下全部输入点被鉴权拦截 |
| 业务逻辑漏洞（越权、流程跳过、金额篡改） | 同上，需账号 |
| 文件上传漏洞实证 | 上传接口需认证；未授权上传已排除 |
| 鉴权与会话深度测试（会话固定、超时、登出失效） | 无账号，无法取得有效会话 |
| 第三方组件 CVE 利用 | jQuery 3.5.1 / Laravel —— 未暴露精确版本号，且主动探测属扫描器范畴 |
| 高端口与非 Web 服务 | 端口扫描属禁止范畴，未执行 |
| `mail.jiaoyu.cn` | 非 Web 攻击面，未测 |
| `eol.cn` 系关联域名 | 归属不同主体，**明确范围外，未触碰** |

> ### ⚠️ 结论边界声明
> **「未扫到」不等于「不存在」。** 本次测试受限于补天规则
> （禁扫描器、禁并发、禁爆破、禁触碰用户数据）与**缺少测试账号**，
> 仅完成了**未登录态下的只读攻击面**评估。
> 该站点**已登录态**的攻击面（越权、业务逻辑、上传）**完全未覆盖**，
> 本报告**不能**作为「该站点安全」的证明。

---

## 7. 补天提交规范对照与提交稿

### 7.1 官方提交模板 6 项（依据 butian.net/Article/content/id/543）

以 **J-01 / `qmt.jiaoyu.cn`** 为准：

| # | 官方要求项 | 本报告对应内容 | 状态 |
|---|---|---|---|
| 1 | **漏洞 URL** | `https://qmt.jiaoyu.cn/` | ✅ |
| 2 | **归属证明** | **已命令行取证**：版权所有「北京中教互联教育科技有限公司」+ 京ICP证140769号 + 京ICP备2022007846号-1（§1.2） | ✅ **已备** |
| 3 | **首页截图（含地址栏）** | 需浏览器访问 `https://qmt.jiaoyu.cn/` 的完整截图 | ⚠️ **须自行补** |
| 4 | **漏洞证明** | 原始响应头（四个 `value` 占位符）+ 明文 HTTP 301 跳转证据 + 会话 Cookie 缺 Secure | ✅ |
| 5 | **权重选择** | 按 `jiaoyu.cn` 在爱站（aizhan.com）的权重勾选 | ⚠️ **须自行补** |
| 6 | 活动/任务选择 | 若在活动期内需先报名 | ⚠️ 视情况 |

### 7.2 归属证明（可直接引用）

```
版权所有：北京中教互联教育科技有限公司
主体地址：北京市海淀区文慧园北路9号今典花园9号楼-教育在线
ICP 证  ：京ICP证140769号
ICP 备  ：京ICP备2022007846号-1
公安网安备：11010802020236
取证来源：https://www.jiaoyu.cn/js/app.99499624.js（站点自身前端资源）
```

### 7.3 提交稿（可直接复制粘贴）

```
【漏洞名称】qmt.jiaoyu.cn 安全响应头配置为无效占位符导致 HSTS 等防护失效，
            叠加明文 HTTP 可达与会话 Cookie 缺失 Secure，存在会话劫持风险

【厂商名称】北京中教互联教育科技有限公司

【漏洞 URL】https://qmt.jiaoyu.cn/

【归属证明】版权所有：北京中教互联教育科技有限公司（与厂商一致）
           主体地址：北京市海淀区文慧园北路9号今典花园9号楼-教育在线
           京ICP证140769号 / 京ICP备2022007846号-1
           取证来源：https://www.jiaoyu.cn/js/app.99499624.js

【漏洞类型】安全配置错误 / 传输层保护不足

【危害等级】中危（CVSS 3.1 6.8 / CVSS 4.0 6.4）

【漏洞描述】
目标站点响应头中 Strict-Transport-Security、Referrer-Policy、
X-Permitted-Cross-Domain-Policies、X-Download-Options 四项的值被配置为
字面量字符串 "value"（模板占位符未替换），浏览器按无效指令忽略，
导致 HSTS 等防护全部失效。同时：
 1. 明文 HTTP（http://qmt.jiaoyu.cn/）实测返回 **301 跳转** HTTPS —— 但跳转由服务端返回，未缓存 HSTS 的客户端的首次明文请求已暴露（2026-09-22 更正）；
  2. 会话 Cookie laravel_session 未设置 Secure 属性，且未声明 SameSite。
三者叠加，攻击者处于中间人位置时可直接截获会话凭据。

【复现步骤】
1. curl -sI https://qmt.jiaoyu.cn/
   观察到以下四项响应头的值均为字面量 "value"：
     Strict-Transport-Security: value
     Referrer-Policy: value
     X-Permitted-Cross-Domain-Policies: value
     X-Download-Options: value
   以及 Set-Cookie: laravel_session=...; expires=...; Max-Age=7200; path=/; httponly
   —— 注意其中没有 Secure，也没有 SameSite。

2. curl -s -D - -o nul http://qmt.jiaoyu.cn/     （请勿跟随跳转）
   观察到 HTTP/1.1 301 Moved Permanently，Location: https://qmt.jiaoyu.cn/
   说明：站点确实做了 HTTPS 跳转，明文 HTTP 不返回任何页面正文；
   但 301 是服务端收到明文请求之后才返回的，该请求本身已走明文链路并携带
   上述缺 Secure 的 laravel_session，中间人可在跳转发生前完成截获。
   （若用会跟随 30x 的客户端，看到的是跳转后 HTTPS 落地页的 200，
     与"明文是否跳转"无关，请勿据此否定本条。）

3. 综合：
   HSTS 值为无效占位符 "value" → 浏览器永不缓存 HSTS，不会主动升级 HTTPS；
   + 明文 HTTP 可达（跳转前的请求已暴露）
   + 会话 Cookie 无 Secure、无 SameSite（默认 Lax，跨站顶级导航仍携带）
   = 会话凭据可被中间人截获。

【影响分析】
laravel_session 为该系统（Laravel）的会话 Cookie，登录后即承载用户身份。
攻击者在公共 WiFi、企业内网或链路中间位置，诱导受害者经 http:// 链接访问该域名
（邮件、旧书签、第三方页面引用等均可），即可在 301 跳转发生前截获会话 Cookie
并接管其会话。由于 HSTS 失效，受害者不存在"仅首次访问有风险"的保护窗口。

【论证边界（如实声明）】
本次测试未取得该系统的登录账号，未能实测"已登录态"下 Cookie 的实际承载内容；
上述 C:H/I:H 评级以"受害者已登录"为前提，依据 Laravel 会话 Cookie 的通用机制推定。
若厂商能提供测试账号，可进一步完成端到端验证。

【修复建议】
1. 修正占位符配置：
   add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
   add_header Referrer-Policy "strict-origin-when-cross-origin" always;
   add_header X-Download-Options "noopen" always;
   add_header X-Permitted-Cross-Domain-Policies "none" always;
2. 80 端口强制 301 跳转 HTTPS
3. Laravel config/session.php 设置 'secure' => true, 'same_site' => 'lax'
4. 建议在 CI 中加入响应头断言，防止占位符再次上线

【权重选择】按 jiaoyu.cn 在爱站的实际百度权重勾选
```

### 7.4 收录性提示

本条属**安全配置错误**类。补天公益 SRC 对纯「响应头缺失/加固建议」类收录率偏低，
但本条的特点是：

- ✅ 有**可复现的原始响应头证据**（占位符 `value`，非常规的"缺失"）
- ✅ 构成**完整利用链**（HSTS 失效 + 明文可达 + Cookie 缺 Secure）而非单点加固建议
- ⚠️ 明文形态为 **301 跳转、不返回正文** —— 这是必须如实写明的减分项，
  论证只能落在「跳转前的明文请求已暴露」上，**绝不可写成"明文返回完整页面"**

> **提交前建议**：先去 `butian.net/Help/plan` 核对「安全配置错误 / 传输层保护不足」
> 是否在当期收录范围。若不在，可考虑改为提交 J-03（框架信息泄露）—— 但后者等级更低。

---

## 8. 证据清单与审计链

| 文件 | 说明 |
|---|---|
| `pentest-orchestrator/probe_*.json` | 9 个子域的限速只读探测证据（含响应头、sha256、指纹分析） |
| `pentest-orchestrator/_jiaoyu_app.js` | 主站前端 bundle（37 个 API 路径、ICP 归属取证来源） |
| `pentest-orchestrator/_jiaoyu_index.html` / `_bk_index.html` | 首页与 bk 平台页面快照 |
| `pentest-orchestrator/_bk_common.js` | bk 公共 JS（请求封装分析） |
| `pentest-orchestrator/_raw_*.txt` | qmt/rmt/www/xuexi 原始响应头硬取证 |

**审计链**：`.sessions/BUTIAN-JIAOYU-20260922.audit.log`（append-only JSONL）

```
COMPLIANCE     全程单线程、间隔≥6s、仅 GET/HEAD/OPTIONS
SCOPE-GUARD    eol.cn 系域名明确范围外，未做任何访问
NO-CRED        未对任何登录接口发起口令尝试（0 次）
NO-USERDATA    未读取或导出任何真实用户数据
NO-SMS         未触发任何短信/邮件发送
NO-DESTRUCT    DELETE 探测仅使用不存在的资源 ID，零破坏
```

---

## 9. 待办事项

1. ⚠️ **补浏览器侧 2 项材料**：
   - 第 3 项「首页截图含地址栏」：浏览器访问 `https://qmt.jiaoyu.cn/`
   - 第 5 项「权重选择」：按 `jiaoyu.cn` 在爱站 `aizhan.com` 的实际百度权重勾选
2. 📋 **提交稿**：直接复制 §7.3
3. 🚫 **切勿提交**：J-04 子域残留（无实际危害）；任何 `detected 🔍` 级条目
4. ✅ **公益 SRC 无需事前报备**，可直接在补天项目页提交
5. 💡 **若想挖到更高危**：需解决「无测试账号」这一阻塞项 ——
   建议向厂商申请测试账号，或将 §4.6 的待验证项留给厂商自查

---

**报告结束** · 生成于 2026-09-22 · 未经授权不得对本报告涉及资产开展进一步测试
