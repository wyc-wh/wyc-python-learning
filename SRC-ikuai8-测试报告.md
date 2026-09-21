# 补天公益 SRC 渗透测试报告

**被测目标**：`www.ikuai8.com`
**厂商**：全讯汇聚网络科技（北京）有限公司（爱快 iKuai）
**平台**：补天漏洞响应平台 · 公益 SRC
**授权编号**：`BUTIAN-GY-PENDING`（**占位值，提交前须替换为补天项目页真实编号**）
**会话 ID**：`BUTIAN-GY-PENDING-20260921-222050`
**测试日期**：2026-09-21
**测试人**：leishen
**报告版本**：v1.0

> **合规声明**：本次测试未执行任何扫描器、并发请求、目录爆破、破坏性 Payload、拒绝服务测试、真实数据读取/导出、横向扩展。全部目标侧交互为 **9 次单线程 GET/HEAD 请求 + 3 次 TLS 握手**，请求间隔 ≥ 6 秒，且仅限授权范围内的 `www.ikuai8.com`。完整操作已写入 append-only 审计链（24 条）。

---

## 目录

1. [授权范围与 SRC 规则边界](#1)
2. [资产清单（被动侦察结果）](#2)
3. [攻击面梳理](#3)
4. [分阶段执行记录](#4)
5. [发现的问题（按风险等级）](#5)
6. [弱口令专项说明](#6)
7. [覆盖度与结论边界](#7)
8. [修复建议](#8)
9. [补天提交规范对照与提交稿](#9)
10. [证据清单与审计链](#10)

---

<a id="1"></a>
## 1. 授权范围与 SRC 规则边界

### 1.1 授权来源与机器可读清单

授权边界已固化为平台可读的 `auth.json`（路径 `pentest-orchestrator/auth.json`），`init` 阶段做 4 项强制校验，任一不过直接 `sys.exit(2)`：

| 校验项 | 结果 |
|---|---|
| 资产在 `in_scope` 内 | ✅ 通过 |
| `auth_id` 与传入一致 | ✅ 通过 |
| 在有效期内（2026-09-21 ~ 2026-12-31） | ✅ 通过 |
| `allow_scanner` 开关 | ⛔ **SCANNER-BLOCKED**（`false`，`autorun` 被拦停） |

`init` 实际输出：

```
[SCANNER-BLOCKED] 授权清单 allow_scanner=false —— autorun 已被禁止
✓ 资产在授权范围内 · 授权编号一致 · 在有效期内
session = BUTIAN-GY-PENDING-20260921-222050
```

### 1.2 范围内资产（in_scope，保守基线）

| 资产 | 说明 |
|---|---|
| `ikuai8.com` | 主域名 |
| `www.ikuai8.com` | **本次唯一实际交互目标** |

> 保守基线原则：仅纳入补天项目页明确公布者。DNS/证书透明日志发现的其他主机名，**一律不自动纳入**。

### 1.3 范围外资产（out_of_scope · 禁测）

已写入 `auth.json` 并**本次未发起过任何一次访问**：

- 被动发现的外部子域：`dev` / `test` / `cloud` / `api` / `youyu.api` / `bbs` / `mail`（阿里企业邮箱托管，非自有系统）/ `ikev2` / `alivpn` / `local` / `pan` / `download` / `patch` / `pkgmanager` / `proxy` / `ivx` / `wuying` / `spadmin` / `spdl` / `spyun` / `phone-auth` / `auth` / `posthog` / `demo` / `ikyun.oss`
- **企业内部域（高危敏感线索，严禁触碰）**：`*.corp.ikuai8.com`（jenkins、jenkins-dev、wiki、wiki-dev、pandawiki、portal、file、ai、sase、ethanbot1）、`*.corp-dev.ikuai8.com`（kiam）、`*.internal.ikuai8.com`（harbor-dev.internal）
- 任何管理后台、路由器固件 OTA、爱快云平台
- 支付 / 下单 / 账号资金相关接口

### 1.4 禁止手法（补天《白帽子行为规范》红线映射）

| 补天红线 | 本平台对应控制 | 本次执行情况 |
|---|---|---|
| 禁止高并发、测试自动化扫描器 | `allow_scanner=false` → `autorun` 硬拦停 | ✅ 未使用任何扫描器（nuclei/nmap/ffuf/gobuster 全部未对目标运行） |
| 禁止大流量、大规模扫描 | `rate_profile=conservative`；手工请求间隔 ≥ 6s | ✅ 目标侧共 9 次请求 |
| 禁止范围外系统 | `in_scope` 白名单校验 | ✅ 仅 `www.ikuai8.com` |
| 禁止未报备的影响业务测试 | `requires_report_before_test=true` | ✅ 无任何写操作、无登录尝试、无凭据测试 |
| 用户额外约束 | 禁破坏性 Payload / DoS / 触碰导出真实用户数据 / 未授权横向扩展 | ✅ 全部遵守 |

### 1.5 定级与提交流程

- **定级参考**：高危 ≥ 7.0 / 中危 4.0–6.9 / 低危 < 4.0（CVSS 3.1 基础分），以补天审核口径为准
- **提交渠道**：补天项目页 → 提交漏洞 → 填写厂商/域名/漏洞类型/危害等级/复现步骤/证明
- **提交前置**：`detected 🔍`（扫描器疑似命中）**不得提交**；须人工复核升级为 `confirmed ✅` 并附证据
- **报备前置**：凡涉及登录/凭据/并发/业务连续性的测试，须先经补天站内信报备审核

---

<a id="2"></a>
## 2. 资产清单（被动侦察结果）

### 2.1 DNS 记录（AliDNS DoH，公共解析服务，不触碰目标服务器）

| 主机 | 记录 | 值 |
|---|---|---|
| `ikuai8.com` | A | `222.217.94.75` |
| `ikuai8.com` | MX | `mx1/2/3.qiye.aliyun.com`（阿里企业邮箱） |
| `ikuai8.com` | NS | `dns17/18.hichina.com`、`vip3/4.alidns.com` |
| `ikuai8.com` | TXT | `utmregg87mv5lu0r222rjddc9h`；`v=spf1 include:spf.qiye.aliyun.com -all` |
| `ikuai8.com` | SOA | `vip3.alidns.com` |
| `www` | CNAME/A | `www.ikuai8.com.w.kunluncan.com` → `116.253.29.46`（阿里云 CDN） |
| `mail` | CNAME | `qiye.aliyun.com` |
| `api` | CNAME | `api.ikuai8.com.w.kunluncan.com` |
| `cloud` | A | `8.222.250.189` |
| `dev` | A | `47.96.90.231` |
| `test` | CNAME/A | `test.ikuai8.com.w.kunlungr.com` → `222.217.94.74` |
| `bbs` | CNAME/A | `bbs.ikuai8.com.w.kunluncan.com` → `116.253.29.49` |

**观察**：SPF 为 `-all` 硬失败，配置规范；`www` 走阿里云 CDN（kunluncan）；主域 A 记录与 `test` 同段（`222.217.94.0/24`），疑似同机房。

### 2.2 证书透明日志（crt.sh，226 条记录 / 40 个历史主机名）

| 分类 | 主机名 |
|---|---|
| **已在范围内** | `ikuai8.com`、`www.ikuai8.com` |
| 外部业务子域（未授权，禁测） | `api`、`auth`、`phone-auth`、`bbs`、`dev`、`demo`、`download`、`patch`、`pkgmanager`、`proxy`、`ivx`、`wuying`、`spadmin`、`spdl`、`spyun`、`posthog`、`mail`、`pan`、`local`、`ikev2`、`alivpn`、`ikyun.oss`、`youyu.api` |
| **企业内部域（敏感，禁测）** | `corp`、`ai.corp`、`portal.corp`、`file.corp`、`pandawiki.corp`、`posthog.corp`、`sase.corp`、`wiki.corp`、`wiki-dev.corp`、`jenkins.corp`、`jenkins-dev.corp`、`ethanbot1.corp`、`kiam.corp`、`kiam.corp-dev`、`harbor-dev.internal` |

签发方分布：Let's Encrypt（多数）、TrustAsia、JoySSL、DigiCert、ZeroSSL。`file.corp` 使用 DigiCert OV 证书，属较重要内部资产。

### 2.3 Web 站点技术栈（单次手工访问取证）

```
GET https://www.ikuai8.com/  →  200
Server: Tengine
Content-Type: text/html; charset=utf-8
Set-Cookie: f2224fa1096458bc94e7e6ef9dc9833a=k9cphbnu0okjksqh2rmeosd2k8; path=/; HttpOnly
Title: 爱快 iKuai-商业场景网络解决方案提供商
```

- **Web 服务器**：Tengine（阿里基于 Nginx 的分支）
- **模板目录**：`/templates/ikuaitemplate/`（自定义模板）
- **CMS 指纹**：首页无 `<meta name="generator">`，但 `robots.txt` 为 Joomla 默认模板原文（见 F-03）
- **传输层**：协商 **TLSv1.3 / TLS_AES_128_GCM_SHA256**；**TLS 1.0 / 1.1 已拒绝** ✅

### 2.4 站点结构（sitemap.xml，421 条 URL）

| 路径前缀 | 性质 |
|---|---|
| `/product/{yjcp,rjcp}` | 产品页 |
| `/program/menuikuai*.html` | 解决方案（校园/企业/餐饮/培训） |
| `/news/*` | 新闻、售后 |
| `/networks/*` | 场景方案 |
| `/contact-us/{oem,join,channel}` | 商务合作 |
| `/zhic/{install,cjwt,spjc,ymgn,alzx}` | 支持中心（安装/常见问题/视频教程/功能/案例） |

**关键结论**：421 条 URL 中 **动态参数型入口为 0**（无 `.php` / `.asp` / `?query`），站点为**全静态化企业官网**。

---

<a id="3"></a>
## 3. 攻击面梳理

| 攻击面 | 当前观察 | 手工测试方法（报备后） | 预期风险 |
|---|---|---|---|
| **Web 应用** | 全静态化展示站，421 URL 无动态入口 | 逐页核查表单/搜索/留言功能（本站未发现）；核查 catch-all 回退逻辑 | 低（注入类面极小） |
| **接口** | 主站无 REST/API 路径暴露；`api`/`youyu.api` 在范围外 | 仅当项目页将 `api` 列入范围时，用浏览器抓包观察业务接口，检查越权/IDOR/未鉴权 | 中（需授权） |
| **鉴权与会话** | 存在 `Set-Cookie`（HttpOnly，**缺 Secure / SameSite**）；站点无登录入口 | 确认该 Cookie 是否承载身份态；检查会话固定/超时/登出失效 | **中（见 F-01）** |
| **业务流转** | 官网无交易/工单/注册流程；商务合作页为联系方式展示 | 若项目页含电商/渠道系统，再测订单金额篡改、流程跳过 | 低（本站无） |
| **文件上传下载** | `download`/`patch`/`pkgmanager`/`spdl` 在范围外；主站仅静态资源 | 若授权，验证上传点后缀白名单、内容校验、存储域隔离 | 未知（需授权） |
| **第三方组件与配置** | Tengine；无暴露版本号的 JS 组件；`robots.txt` 为 Joomla 默认模板残留 | 核查组件版本与已知 CVE；核查响应头与目录配置 | **低~信息（见 F-02/F-03）** |

---

<a id="4"></a>
## 4. 分阶段执行记录

### 阶段 1 · 信息收集 ✅ 已完成

| 动作 | 方式 | 是否触碰目标 | 结果 |
|---|---|---|---|
| DNS 记录采集 | AliDNS DoH | ❌ 否 | 12 组记录 |
| 子域/主机名枚举 | crt.sh 证书透明日志 | ❌ 否 | 226 条 / 40 主机名 |
| 站点结构盘点 | `sitemap.xml` 单次 GET | ✅ 是（1 次） | 421 URL，0 动态入口 |
| 技术栈识别 | 首页单次 GET + TLS 握手 | ✅ 是（2 次 + 3 次握手） | Tengine / TLS1.3 |
| 子域枚举工具（subfinder） | 无 API Key 返回 0 | — | 跳过，未用扫描器 |

### 阶段 2 · 漏洞发现 ✅ 已完成（手工、极小规模）

| 探测 | 方法 | 结果 |
|---|---|---|
| `/robots.txt` | GET ×1 | 200，Joomla 默认模板 |
| `http://`（明文） | GET ×1 | 200，不跳转 HTTPS |
| `/administrator/` | GET ×1 | 200，但响应体与首页 sha256 一致 → 软 404 |
| `/installation/` | GET ×1 | 404 |
| 安全响应头 | 响应头解析 | HSTS/XFO/CSP/Referrer-Policy/XCTO 全部缺失 |

**未执行**：目录爆破、参数 Fuzz、漏洞模板匹配、CMS CVE 探测 —— 均属补天禁止的自动化扫描范畴。

### 阶段 3 · 可利用性验证 ⚠️ 部分受限

- 已验证（无害、只读）：**catch-all 软 404 行为**（`/administrator/` 与首页字节一致）
- 已验证（无害）：**TLS 1.0/1.1 已禁用**（握手被拒）
- **未执行**：任何利用性验证（注入、越权、上传、RCE）。原因：(a) 主站无动态输入点；(b) 涉及业务系统的测试需补天报备；(c) 禁止破坏性 Payload

### 阶段 4 · 危害评估 ✅ 已完成

见第 5 节，含 CVSS 3.1/4.0 双标准评分与置信度标注。

### 阶段 5 · 证据固定 ✅ 已完成

- 原始响应落盘：`recon_passive.json`、`recon_manual.json`、`recon_confirm.json`、`recon_sitemap.json`
- 响应体 SHA-256 摘要已记录（首页 `ea964e5455ecc802e54e847fc224bc949a745e3f8f8c15c65425c51d1c5a975f`；sitemap `49522e6d28fcdbf4ed224f30b2e5d4135b22d122c9004d165563dc4e4dcadc5b`）
- 操作写入 append-only 审计链（24 条，含 11 条本次新增）

### 阶段 6 · 报告撰写 ✅ 本文档

---

<a id="5"></a>
## 5. 发现的问题（按风险等级）

### 🟡 中危 F-01：明文 HTTP 可达且未跳转 HTTPS，会话 Cookie 未设置 `Secure` 属性

- **置信度**：`confirmed ✅`（响应头实测，非扫描器推断）
- **CVSS 3.1**：**5.3**（AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N）
- **CVSS 4.0**：**4.8**（AV:N/AC:H/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N）
- **位置**：`http://www.ikuai8.com/`（任意路径）

**复现步骤**

1. 发起明文 HTTP 请求，观察是否跳转：

```http
GET / HTTP/1.1
Host: www.ikuai8.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
```

2. 观察响应（**无 `Location` 跳转头，直接 200 返回完整页面**）：

```http
HTTP/1.1 200 OK
Server: Tengine
Content-Type: text/html; charset=utf-8
Set-Cookie: f2224fa1096458bc94e7e6ef9dc9833a=pim154e36ho9ji0tnk6chr2bsi; path=/; HttpOnly
```

3. 对比 HTTPS 响应头，确认 `Strict-Transport-Security` **缺失**（因此浏览器不会自动升级为 HTTPS，用户首次访问/手动输入域名时仍走明文）。

**影响分析**

- 站点在 80 端口明文可达且不重定向，攻击者处于同一网络（公共 Wi-Fi、运营商链路、企业旁路）时可实施中间人劫持；
- 会话 Cookie 仅有 `HttpOnly`，**缺 `Secure`**，因此会随明文 HTTP 请求直接以裸文本传输，可被旁路嗅探窃取；
- 缺 `SameSite` 属性，存在 CSRF 利用面（需结合具体业务动作）；
- 无 HSTS，无法通过浏览器侧强制 HTTPS 来缓解。
- **危害限定**：本站为静态展示站，未见登录入口，该 Cookie 推测为 CDN/WAF 会话标识而非身份凭据，故**机密性影响按"高"估、实际身份冒用风险取决于该 Cookie 是否承载登录态**，需厂商确认。

---

### 🔵 低危 F-02：安全响应头缺失（HSTS / X-Frame-Options / CSP / Referrer-Policy / X-Content-Type-Options）

- **置信度**：`confirmed ✅`
- **定级**：信息~低危（补天通常不单独收录，建议与 F-01 合并提交）

**证据**（HTTPS 首页响应头实测，仅含 3 项）：

```http
Server: Tengine
Content-Type: text/html; charset=utf-8
Set-Cookie: f2224fa1096458bc94e7e6ef9dc9833a=...; path=/; HttpOnly
```

缺失：`Strict-Transport-Security`、`X-Frame-Options`、`Content-Security-Policy`、`Referrer-Policy`、`X-Content-Type-Options`。

**影响**：点击劫持防护缺失、MIME 嗅探防护缺失、Referer 泄漏、无 CSP 缓冲（一旦将来引入富交互页面，XSS 影响放大）。当前为静态站，实际不可直接利用。

---

### ⚪ 信息级 F-03：`robots.txt` 为 Joomla 默认模板残留，且站点存在全站 catch-all 软 404

- **置信度**：`confirmed ✅`
- **不建议单独提交**（属配置噪音，可在 F-02 中一并说明）

**证据 1** — `GET /robots.txt` 返回 Joomla 官方默认注释与 15 条 `Disallow`：

```
# If the Joomla site is installed within a folder ...
User-agent: *
Disallow: /administrator/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
...（共 15 条）
```

**证据 2** — 路径实际不存在（已验证非真实后台泄露）：

```
GET /administrator/  → 200
  sha256 = ea964e5455ecc802e54e847fc224bc949a745e3f8f8c15c65425c51d1c5a975f
GET /               → 200
  sha256 = ea964e5455ecc802e54e847fc224bc949a745e3f8f8c15c65425c51d1c5a975f
  ⇒ 两者字节完全一致 → catch-all 回退首页（软 404）

GET /installation/  → 404   （安装目录未残留 ✅）
```

**影响**：(a) `robots.txt` 泄露的是模板默认值，会误导攻击者做无效尝试，也说明该文件未随站点改造而更新；(b) **任意不存在路径均返回 200 + 首页内容**，会使所有基于状态码的探测/扫描器产生大量误报，并污染访问日志与安全审计规则。

---

### ⚪ 信息级 F-04：企业内部系统主机名经证书透明日志暴露（**企业自查项，不作为 SRC 漏洞提交**）

- **置信度**：`confirmed ✅`（公共数据库实测）
- **处置**：已全部写入 `auth.json` 的 `out_of_scope`，**本次未发起任何访问**

暴露的内部主机名包括：`jenkins.corp.ikuai8.com`、`jenkins-dev.corp.ikuai8.com`、`harbor-dev.internal.ikuai8.com`、`wiki.corp.ikuai8.com`、`wiki-dev.corp.ikuai8.com`、`pandawiki.corp.ikuai8.com`、`kiam.corp.ikuai8.com`、`kiam.corp-dev.ikuai8.com`、`portal.corp.ikuai8.com`、`file.corp.ikuai8.com`（DigiCert OV 证书）、`sase.corp.ikuai8.com`、`posthog.corp.ikuai8.com`、`ai.corp.ikuai8.com`、`ethanbot1.corp.ikuai8.com`。

**影响**：CI（Jenkins）、镜像仓库（Harbor）、密钥/身份系统（KIAM）、内部 Wiki 等主机名一旦对外签发证书并可解析，即构成内网资产暴露面，易被定向攻击（Jenkins 未授权访问、Harbor 弱口令、Wiki 信息泄露等）。**建议厂商自查这些系统是否存在公网可达、是否启用强认证与访问控制。**

---

<a id="6"></a>
## 6. 弱口令专项说明（对应截图中的「漏洞类型：弱口令」）

### 6.1 关键结论：弱口令攻击面不在 `www.ikuai8.com`

- `sitemap.xml` 中 **421 条 URL，动态入口 0 条**；
- 首页及站点结构中**未发现登录页、注册页、用户中心**；
- `/administrator/` 为 catch-all 软 404，**不存在真实后台登录入口**；
- 主站唯一的 Cookie 未与任何登录流程关联。

⇒ **在 `www.ikuai8.com` 上测试弱口令，不存在可用目标。** 截图中选择的「弱口令」类型对应的是其他资产（爱快云平台、渠道/代理后台、论坛、或路由器设备管理端）。

> **范围判定修正（依据补天官方 FAQ）**：公益 SRC **不提供资产白名单**，其官方定义为「厂商注册成为公益SRC企业用户后，白帽子随机发现漏洞并提交，平台审核后通知企业认领」。
> 因此范围边界的正确判据不是"项目页列表"，而是 **① 资产归属能否证明**（ICP 备案主体 / 版权声明 / 官网导航链接）+ **② 是否属于该公益SRC项目下历史已收录漏洞的资产分布**。
> 上述其他资产必须先完成归属证明，才能视为可测。

### 6.2 若确认含登录型资产 —— 报备后的合规测试方案

1. **先报备**：依据《白帽子行为规范》，凡"可能影响业务连续性、用户数据安全或系统稳定性的测试（如核心功能篡改、批量数据操作等）"，**必须提前向补天平台报备，经审核并与厂商确认后方可实施**。报备对象为**补天平台**（站内信 / 白帽咨询 010-56509093 / 官方群），不是自行联系厂商。
   - 单次登录尝试（≤ 5 次、低频）通常不需报备；
   - **字典爆破 / 撞库 / 批量账号验证一律必须报备**，且因平台禁止自动化扫描器，获批概率低。
2. **禁用字典爆破**：补天明令禁止高并发。仅允许 **单账号 × ≤ 5 次常识性口令** 的验证，两次尝试间隔 ≥ 10 秒。
3. **优先验证防御机制而非穷举**：重点确认是否存在 (a) 图形/滑块验证码 (b) 失败次数锁定或阶梯延时 (c) 默认初始口令是否未强制修改 (d) 口令复杂度策略 (e) 明文传输。
4. **严禁**：遍历用户名、撞库、使用公开字典、多线程、对短信/邮箱验证码接口做轰炸。
5. **证据固定**：仅记录「成功/失败」判定与响应长度/状态码差异，**不得记录或导出任何账号、手机号、密码明文**。
6. **发现即停**：一旦登录成功，**立即停止**，不再做进一步横向或数据操作，仅截最小必要证明。

---

<a id="7"></a>
## 7. 覆盖度与结论边界（**必读**）

### 7.1 本次已覆盖

| 项目 | 覆盖 |
|---|---|
| DNS / 证书透明日志等被动情报 | ✅ 充分 |
| 站点结构与技术栈识别 | ✅ 充分 |
| 明文 HTTP 与 Cookie 安全属性 | ✅ 实测 |
| 安全响应头 | ✅ 实测 |
| TLS 协议版本 | ✅ 实测（1.0/1.1 已禁，协商 1.3） |
| Joomla 默认配置残留 / catch-all 行为 | ✅ 实测 |

### 7.2 本次**未**覆盖（不得据此推断不存在漏洞）

| 未覆盖项 | 原因 |
|---|---|
| 目录/文件爆破、备份与敏感文件枚举 | 补天禁止自动化扫描；仅手工核查 2 条路径 |
| 参数级注入（SQLi / XSS / 命令注入 / SSRF / SSTI） | 主站无动态参数入口；且需报备 |
| 业务逻辑漏洞（越权、IDOR、流程跳过、金额篡改） | 主站无业务流程；相关系统在范围外 |
| 鉴权与会话深度测试（会话固定、超时、登出失效） | 无登录入口 |
| 文件上传下载点 | 相关子域在范围外 |
| 第三方组件 CVE 利用 | 主站未暴露组件版本；主动探测属扫描器范畴 |
| 子域接管、CNAME 劫持 | 子域均在范围外 |
| OOB / 盲漏洞（blind SSRF、log4j 类） | 需回连外部服务，属影响业务测试，须报备 |
| 高端口与非 Web 服务 | 端口扫描属禁止范畴，未执行 |
| 企业内网域（`corp.*` / `internal.*`） | 明确范围外，未触碰 |

> **结论边界声明**：本报告**不代表** `www.ikuai8.com` 不存在上述未覆盖类别的漏洞。本次是受限合规条件下的**部分面**测试，未扫到 ≠ 不存在。任何结论引用本报告时须同时引用本节。

---

<a id="8"></a>
## 8. 修复建议

### P1 · 立即修复（F-01）

```nginx
# 1) 80 端口强制跳转 HTTPS，不再返回业务内容
server {
    listen 80;
    server_name www.ikuai8.com ikuai8.com;
    return 301 https://$host$request_uri;
}

# 2) HTTPS 站点启用 HSTS
server {
    listen 443 ssl http2;
    server_name www.ikuai8.com ikuai8.com;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # 3) Cookie 补齐 Secure + SameSite（Tengine/Nginx ≥ 1.19.3）
    proxy_cookie_flags ~ Secure SameSite=Lax;
    # 或在应用层：setcookie($n, $v, ['secure'=>true,'httponly'=>true,'samesite'=>'Lax','path'=>'/']);
}
```

### P2 · 加固（F-02）

```nginx
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'; img-src 'self' data: https:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'" always;
```

> CSP 建议先用 `Content-Security-Policy-Report-Only` 灰度观察，避免误伤页面。

### P3 · 清理（F-03）

- 按实际站点重写 `robots.txt`，删除 Joomla 默认注释与不存在的 `Disallow` 路径；
- 修正 catch-all 规则：不存在的路径应返回 **404**（而非 200 + 首页内容），避免日志与 WAF 误判。

### P4 · 企业自查（F-04，非 SRC 提交项）

- 收敛 `*.corp.ikuai8.com` / `*.corp-dev` / `*.internal` 的公网解析与证书签发；
- Jenkins / Harbor / KIAM / Wiki 等：确认是否公网可达，强制 SSO + MFA，关闭匿名访问，及时打补丁；
- 内网系统证书建议改用内网 CA 或不签发公网可信证书，避免资产暴露。

---

<a id="9"></a>
## 9. 补天提交规范对照与提交稿

### 9.0 补天【公益 SRC 官方提交模板】6 项（依据 butian.net/Article/content/id/543）

| # | 官方要求项 | 本报告对应内容 | 状态 |
|---|---|---|---|
| 1 | **漏洞 URL** | `http://www.ikuai8.com/` | ✅ |
| 2 | **归属证明** | 需 ICP 备案主体为「全讯汇聚网络科技（北京）有限公司」的查询截图 | ⚠️ **须自行补截图** |
| 3 | **首页截图（含地址栏）** | 需浏览器访问首页、地址栏可见的完整截图 | ⚠️ **须自行补截图** |
| 4 | **漏洞证明** | 原始请求/响应头 + SHA-256 摘要（见 F-01） | ✅ |
| 5 | **权重选择** | 按主域名 `ikuai8.com` 在爱站（aizhan.com）的权重选择 | ⚠️ **提交时按实际权重勾选** |
| 6 | 活动/任务选择 | 若在活动期内，需先在活动中心报名 | ⚠️ 视情况 |

> **缺少第 2/3/5 项会直接影响审核结果** —— 这三项是我（命令行环境）无法代劳的，必须你在浏览器里补齐。

### 9.1 规范对照

| 补天要求 | 本报告 | 状态 |
|---|---|---|
| 厂商名称准确 | 全讯汇聚网络科技（北京）有限公司 | ✅ |
| **资产归属可证明** | `ikuai8.com` 备案主体需与厂商一致 | ⚠️ 待补备案截图 |
| 漏洞类型明确 | 安全配置错误 / 传输层保护不足 | ✅ |
| 危害等级 | 中危（CVSS 3.1 5.3） | ✅ |
| 详细复现步骤 | 见 F-01 | ✅ |
| 请求/响应证明 | 原始响应头 + SHA-256 摘要 | ✅ |
| 影响分析 | 见 F-01 影响分析 | ✅ |
| 修复建议 | 见第 8 节 | ✅ |
| 不使用扫描器产出 | 全部人工实测 | ✅ |
| 不触碰范围外资产 | 40 主机名中仅测 1 个在范围内者 | ✅ |

> **收录风险提示**：补天官方收录细则见 `butian.net/Help/plan`。纯"安全响应头缺失/配置加固建议"类通常在公益 SRC 不被收录。
> 本条 F-01 的可收录性取决于能否证明该 Cookie **承载身份态** —— 若仅证明"缺 Secure 属性"而无实际劫持后果，大概率被判"影响不大、难以造成实际影响"而驳回。
> **建议提交前先去 `butian.net/Help/plan` 核对该类是否在收录范围内。**

### 9.2 提交稿（可直接粘贴）

> **标题**：爱快官网 www.ikuai8.com 明文 HTTP 可访问且会话 Cookie 未设置 Secure 属性，存在中间人劫持风险
>
> **厂商**：全讯汇聚网络科技（北京）有限公司
> **域名**：www.ikuai8.com
> **漏洞类型**：安全配置错误 / 传输层保护不足
> **危害等级**：中危（CVSS 3.1 5.3）
>
> **漏洞URL**：`http://www.ikuai8.com/`
>
> **复现步骤**：
> 1. 访问 `http://www.ikuai8.com/`（明文 HTTP）；
> 2. 服务端返回 200 并直接输出完整页面，未返回 301/302 跳转至 HTTPS；
> 3. 响应头中 `Set-Cookie: f2224fa1096458bc94e7e6ef9dc9833a=xxx; path=/; HttpOnly`，仅含 HttpOnly，**无 Secure、无 SameSite**；
> 4. HTTPS 响应头中**无 `Strict-Transport-Security`**，浏览器不会强制升级 HTTPS。
>
> **归属证明**：（此处贴 ICP 备案查询截图，主体须为「全讯汇聚网络科技（北京）有限公司」）
> **首页截图**：（此处贴浏览器访问 https://www.ikuai8.com/ 且地址栏可见的完整截图）
> **权重选择**：（按 ikuai8.com 在爱站 aizhan.com 的实际百度权重勾选）
>
> **证明**：
> ```
> GET / HTTP/1.1
> Host: www.ikuai8.com
>
> HTTP/1.1 200 OK
> Server: Tengine
> Content-Type: text/html; charset=utf-8
> Set-Cookie: f2224fa1096458bc94e7e6ef9dc9833a=pim154e36ho9ji0tnk6chr2bsi; path=/; HttpOnly
> （无 Location 跳转、无 Strict-Transport-Security）
> ```
>
> **危害分析**：站点明文可达且不跳转 HTTPS，攻击者处于同一网络时可实施中间人攻击；会话 Cookie 缺 `Secure` 属性，会在明文请求中以裸文本传输并被嗅探窃取；缺 `SameSite` 存在 CSRF 面；无 HSTS 导致浏览器侧无法强制加密。若该 Cookie 后续承载登录态，可导致会话劫持与身份冒用。
>
> **修复建议**：
> 1. 80 端口配置 `return 301 https://$host$request_uri;`，禁止明文返回业务内容；
> 2. HTTPS 站点添加 `Strict-Transport-Security: max-age=31536000; includeSubDomains`；
> 3. Cookie 补齐 `Secure; SameSite=Lax`（Nginx 可用 `proxy_cookie_flags ~ Secure SameSite=Lax;`）；
> 4. 建议同时补齐 `X-Frame-Options`、`X-Content-Type-Options`、`Referrer-Policy`、`Content-Security-Policy`。

---

<a id="10"></a>
## 10. 证据清单与审计链

### 10.1 落盘证据

| 文件 | 内容 |
|---|---|
| `pentest-orchestrator/recon_passive.json` | 首页响应头/标题、crt.sh 40 主机名 |
| `pentest-orchestrator/recon_manual.json` | robots.txt、sitemap.xml、明文 HTTP 原始响应（含 SHA-256） |
| `pentest-orchestrator/recon_confirm.json` | 首页 CMS 指纹、`/administrator/` 与 `/installation/` 判定结果 |
| `pentest-orchestrator/recon_sitemap.json` | 421 条 URL 结构与动态入口统计 |
| `pentest-orchestrator/auth.json` | 授权范围清单（含 40+ 条禁测条目） |
| `.sessions/BUTIAN-GY-PENDING-20260921-222050.audit.log` | append-only 审计链，24 条 |

### 10.2 本次新增审计条目（11 条）

```
RECON-PASSIVE  crt.sh 查询：226 条 / 40 个历史主机名（未触碰目标服务器）
RECON-PASSIVE  AliDNS DoH 解析记录
MANUAL-PROBE   GET /            → 200 Tengine，Cookie HttpOnly 缺 Secure/SameSite
MANUAL-PROBE   GET /robots.txt  → 200 Joomla 默认模板
MANUAL-PROBE   GET /sitemap.xml → 200，421 URL，0 动态入口
MANUAL-PROBE   GET http://      → 200 明文可达，无 HSTS
MANUAL-PROBE   GET /administrator/ → 200 与首页 sha256 一致（软 404）
MANUAL-PROBE   GET /installation/  → 404
TLS-CHECK      TLS1.3 协商，TLS1.0/1.1 已拒绝
SCOPE-GUARD    corp.*/internal.* 主机名已标记禁测，未做任何访问
COMPLIANCE     未执行扫描器/并发/爆破/破坏性Payload/DoS/数据导出
```

### 10.3 提交前必办事项

1. ⚠️ **替换 `auth_id`**：`BUTIAN-GY-PENDING` 为占位值，须替换为补天项目页真实编号后重跑 `init`；
2. ⚠️ **核对资产范围**：登录补天项目页确认 `in_scope` 是否含业务系统（云后台/论坛/API），若含则补充测试；
3. ⚠️ **涉及登录的测试须先报备**；
4. 提交时附本报告第 9.2 节提交稿，勿提交 `detected 🔍` 级条目。

---

**报告结束** · 生成于 2026-09-21 · 未经授权不得对本报告涉及资产开展进一步测试
