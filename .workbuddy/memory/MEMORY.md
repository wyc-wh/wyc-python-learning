# 项目记忆 - 自动挖洞平台（速查）

> 篇幅所限拆分：**详细方法论 / 实现细节 / 评估结论在 `HANDBOOK.md`**，过程记录在 `2026-09-21.md`、`2026-09-22.md`。
> 本文只放「不知道就会犯错」的硬规则。

## 骨架

- `pentest-orchestrator/`：`orchestrator.py`(CLI) `rules_engine.py` `rules/`(R001~R014) `scanners.py`(nmap+nuclei) `cvss.py` `exploit.py` `manual_probe.py` `coverage.py` `evidence_lint.py` `credentials.py` `_lab_cert.py`
- 子命令 `init plan autorun engage verify report status check lint submit coverage`
- 合规闸：授权确认 + 范围校验 + `auth.json` + append-only 审计 + 破坏性阶段禁用 + `allow_scanner=false` 硬开关
- 置信度 `detected🔍`→`confirmed✅`→`exploited💥`；**detected 不得提交 SRC**
- `rate_findings` 重算会重置置信度 → `generate_report` 必须回放 `session["verifications"]`
- CVSS 一律引擎算 `compute_cvss31(8参)`/`compute_cvss40(11参)`；**4.0 只有 N/A/P（UI:R→UI:P）**
- 工具 nmap 7.92 / nuclei v3.11.1 / ffuf / gobuster / feroxbuster / subfinder / amass / httpx / sqlmap / wafw00f；缺 nikto whatweb hydra john
- git `~/.workbuddy/binaries/PortableGit/versions/1.2.0/cmd/git.exe`。**沙箱 bash 的 PATH 常坏**（`dirname/ls: command not found`）→ 用 PowerShell，或先 `export PATH=".../PortableGit/versions/1.2.0/usr/bin:.../bin:/c/Windows/System32:$PATH"`

## 补天公益 SRC

- **不需核备案、不需事先报备**（"报备"条款只针对专属 SRC/众测）；**无资产白名单**。范围判据 = 官网首页公开链出 + 版权/主体一致；ICP 只作提交第 2 项「归属证明」
- 红线：禁自动化扫描器 / 高并发 / 破坏性 / 用户数据 / 范围外 / 未授权横向。自律：单线程、间隔 ≥6s、单次 ≤10 请求、全部写审计链
- 提交模板 6 项：①URL ②归属证明 ③首页截图含地址栏 ④漏洞证明 ⑤爱站权重 ⑥活动任务（②③⑤ 需人工）
- 教训：平台规则先查官方文档，别靠行业通例推断

## 通用工程坑

- **nuclei 必须 `-no-interactsh`**（约 710 模板回连 oast.* 被网关掐断，零输出无提示）
- 去重两层：`(template_id,matched_at)` + `(类别,归一化位置)`；`type=generic` 视为未知类别
- **「工具没装」先怀疑调用侧**：中文 Windows `encoding="utf-8"` 丢输出；端口列表别 `split()`（nmap 会把端口串当主机名）。**耗时=超时整数倍→参数拼错；秒返空→编码问题**
- Windows 不能用 SO_REUSEADDR 探测端口；nmap 无 Npcap 时 `-sV` 挂起→降级 `-sT`；Go 版本号先剥 ANSI 色码
- 合规闸统一 **rc=2 + stderr**（`sys.exit(str)` 是 rc=1）；`_find_exe` 认 `.bat/.cmd/.py`；`python -m <pkg>` 不万能
- `git ls-files` 非 ASCII 转八进制 → `-z`+escape_decode；中文名 ENOSYS → `--ignore-errors`

## 证据铁律（两次翻车换来）

1. **「缺失」与「值为 None」必须字面可区分**：缺失写 `<未声明>` + `*_present` 布尔。**属性不存在的中间表示不能复用「有值」的值域**（曾把缺失读成 `SameSite=None`，写出「Chrome 会拒绝」这类自我削弱附注）
2. **改了底层函数 ≠ 修好调用点**（`fetch()` 加了 `follow_redirect`，但 `main()` 仍默认跟随）→ 端到端复跑并比对原始输出
3. **urllib 默认跟随 30x**：会把「明文 301」记成「200 不跳转」。判跳转须 `redirect_request` 返 None，再从 `HTTPError.headers` 取 Location
4. **写前自问：这句措辞在帮我还是在帮厂商？** 真实减分项如实写；误读出的必须删
5. **多值头会被 `dict(headers)` 静默截断** → 同发 `XSRF-TOKEN` + `laravel_session` 时真会话 Cookie 丢失。Set-Cookie 必须单独存多值列表 `_all_set_cookies`，解析优先取它
6. **CSRF token ≠ 会话 Cookie**：两者正则必须互斥，否则「会话劫持链」会被一句话驳回
7. **非 200 不能静默丢弃**（既不产 finding 也不产 negative 会违反「排除必产 negative」）；≥500 或体积 ≥3× 基线 → 标 `needs_manual_check`（「未取得可判定响应」）
8. **异常响应先取证再下结论**：引擎只记状态码 + 字节数，看不到正文。`rmt` 500/38659B 直觉是 Laravel 调试页，**实为 WAF 拦截页**（`Server: ZS-Proxy21/v201`）；`qmt` 404/11043B 是站点自身 404 页。**按表象写就是幻觉发现。**
9. **前置 WAF 污染状态码判据**：同一路径可能返回拦截页 / 跳转 / 自定义错误页 → 「未命中」= 「未取得可判定证据」，**不等于**「路径不存在或已防护」，必须写进结论边界

## 措辞铁律（会直接印进报告和提交稿）

- 规则名 / 发现名**不写主观词**：「不跳转」→ 改；「返回完整内容」→ 实测 `{bytes}B`。**能被机器验证的写事实，不能验证的别写形容词**
- 提交稿「影响分析」由 CVSS 向量推出「利用前提」(AV/AC/PR/UI/S) + 「安全影响」(C/I/A)，不写套话

## 测试基建铁律

1. 会写真实配置文件的测试**先备份再还原**（曾删掉真实 auth.json）
2. 环境隔离 `PENTEST_AUTH`/`PENTEST_SESSIONS` + `tempfile.mkdtemp()`
3. **靶场红时先分辨「数据脏」还是「代码错」**（P3 首跑 6 红 4 条数据不合格；P4 首跑 6 红 2 条 cookie 名写错）。**别改断言迁就**
4. **靶场必须自检 `status=None`**：忘 `verify_tls=False` 会让 HTTPS 全失败却表现为「站点没内容」→ **假通过**（P2/P4 各踩一次）
5. **规则数量别硬编码**，从 `rules.load_rules()` 动态取
6. **禁止用 `python -c`/bash 内联写含反引号的中文长文本**（反引号被 bash 当命令替换执行，内容静默挖空，踩过**两次**）→ 一律用 Write 写 .py 脚本再执行

## 响应分类与 R014（P1）

- **`base.classify_response()`**（`rules/data/error_pages.json` 120 条）把响应分成
  报错页 / 拦截页 / 拒绝页 / 目录列举。三条硬边界：①**过泛词**（`error`/`line`/
  `Internal Server Error`/`server at`）只作旁证，单独采信 = 抑制器自己变假阳性来源
  ②**`listing`（Index of / Parent Directory）是正向证据**（CWE-548），禁止用于抑制
  ③命中后要**写进措辞**（「实测为 WAF/拦截页（waf:创宇盾）」），不写「疑似」
- **非 200 也必须带分类结论**：`/storage/logs/laravel.log` 返 405/1841B 看着像
  「未取得 200 内容」，实为**阿里云统一错误页**（`errors.aliyun.com`）→ 含义是
  「请求在边缘节点就被拦了」，源站有没有这个文件**根本没被判定**
- **跨路径一致性**：多条**不同**路径返回**字节完全相同**的非 200 响应 = 站点通用
  错误页模板，不是路径内容（qmt：`.git/config` 与 `laravel.log` 都是 404/11043B/
  同 sha256）。可据此把「需人工查看响应体」降级，但**不解除**「文件是否存在」的疑问
  —— WAF 也可能对一批路径返回同一张拦截页
- **R014（凭据/密钥暴露，0 额外请求）**：扫前面规则已取回的响应，排 ORDER 末尾。
  判据必须「敏感名字 + 赋值号 + 引号值」三要素 + 占位符/低熵过滤
  （**`\b` 在 `your_api_key` 上不成立**，`_` 属于 `\w`，占位符规则要显式接受分隔符/数字/结尾）。
  **隐私铁律**：只记类别名 + 次数 + 值的长度与字符集，**不记值也不记其哈希**
  （低熵口令哈希可反查）。与 R008 重叠时以 R008 为准（`shared["sensitive_hit_urls"]` 去重）
- **字典库原料「不读就信」是最大风险**：`HTTP/errors.txt` 曾被误判为「WAF 拦截页特征表」，
  读过原文才发现是 **SQL/框架报错串表**；`secret-keywords.txt` 69 行是裸关键词，
  单独使用会命中每一个网页。故构建脚本**强制逐条定性**（漏/多/重复一律报错退出）

## 台账

- **ikuai8.com**：F-10 高危（Discuz! X3.3 EOL + 登录失败计数失效 7.4/7.7）、F-05(6.5)。R012 试跑 8 个 in_scope 资产未命中未授权访问；`demo.`/`icc.` 的 SPA bundle 匿名可下载（各自提取出 `/fs/*`、`/admin/index/*` 与 `/console/*` 清单），匿名请求被 catch-all 兜回首页/404，**需登录态才能验证鉴权**（待办）。
  另：`bbs.ikuai8.com` 的 `/.env`、`/.git/config` 均返回 **405/1841B**，正文是**阿里云边缘节点统一错误页**（`errors.aliyun.com` + `data-spm`）→ 路径是否存在未判定，别再重复试探
- **jiaoyu.cn**：J-01 中危（qmt 安全头占位符失效 6.8/6.4）。11 资产全重跑（覆盖 100/A）无高危，**匿名侧确实扎实**；登录态（R010/R011）因无 Cookie 未覆盖 —— 唯一可能翻高危的方向
- **⚠️ jiaoyu 的 SPA bundle 全在认证墙后**（登录页是纯静态「无权限页面」0 个 script，404 也 302 回 login）→「从 bundle 捞 API 清单」对该站无效，**勿重复尝试**。要挖只能靠登录 Cookie（**2 小时过期**，`laravel_session`+`XSRF-TOKEN` 缺一不可，三个子站不通用）

## 索引

- `HANDBOOK.md` —— 手工只读手法 / 「版本命中官方公告」打法 / 规则引擎 R001-R013 详解 / 证据 lint / 框架指纹 / 覆盖度量化 / 登录态建模 / 图表导出 / 已评估结论（PentAGI、字典库）
- 工程内 `RULES.md` —— 规则清单与每条适用边界
